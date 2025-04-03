package vpnless

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vpnless/vpnless/devicestore"
	"go.uber.org/zap"
)

// errAuthorizedDeviceNotFound is returned when revoking a device that is not in the authorized list.
var errAuthorizedDeviceNotFound = errors.New("device not found in authorized list")

// DeviceAuthCookieMaxAgeSec is the Max-Age (seconds) for the HTTP-only device token cookie (5×365-day years).
const DeviceAuthCookieMaxAgeSec = 5 * 365 * 86400

// loggedDeviceStorePaths dedupes "store ready" logs when many vpnless handler instances share one DB path.
var loggedDeviceStorePaths sync.Map

func init() {
	caddy.RegisterModule(DeviceAuth{})
	httpcaddyfile.RegisterHandlerDirective("device_auth", parseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("vpnless", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("device_auth", httpcaddyfile.After, "basic_auth")
	httpcaddyfile.RegisterDirectiveOrder("vpnless", httpcaddyfile.After, "basic_auth")
	httpcaddyfile.RegisterGlobalOption("vpnless", parseGlobalVPNLessOption)
}

// parseCaddyfile unmarshals the device_auth directive into a DeviceAuth handler.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m DeviceAuth
	if raw := h.Option("vpnless"); raw != nil {
		switch cfg := raw.(type) {
		case vpnlessGlobalOptions:
			applyGlobalVPNLessDefaults(&m, cfg)
		case *vpnlessGlobalOptions:
			if cfg != nil {
				applyGlobalVPNLessDefaults(&m, *cfg)
			}
		}
	}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

type vpnlessGlobalOptions struct {
	StoragePath        string
	PairingPath        string
	ApprovalPath       string
	CookieName         string
	CookieDomain       string
	AdminHost          string
	ApprovalBasicAuth  string
	AdminTrustDuration string
	DockerHost         string
	TrustedProxyCIDRs  []string
}

func applyGlobalVPNLessDefaults(m *DeviceAuth, cfg vpnlessGlobalOptions) {
	if cfg.StoragePath != "" {
		m.StoragePath = cfg.StoragePath
	}
	if cfg.PairingPath != "" {
		m.PairingPath = cfg.PairingPath
	}
	if cfg.ApprovalPath != "" {
		m.ApprovalPath = cfg.ApprovalPath
	}
	if cfg.CookieName != "" {
		m.CookieName = cfg.CookieName
	}
	if cfg.CookieDomain != "" {
		m.CookieDomain = cfg.CookieDomain
	}
	if cfg.AdminHost != "" {
		m.AdminHost = cfg.AdminHost
	}
	if cfg.ApprovalBasicAuth != "" {
		m.ApprovalBasicAuth = cfg.ApprovalBasicAuth
	}
	if cfg.AdminTrustDuration != "" {
		m.AdminTrustDuration = cfg.AdminTrustDuration
	}
	if cfg.DockerHost != "" {
		m.DockerHost = cfg.DockerHost
	}
	if len(cfg.TrustedProxyCIDRs) > 0 {
		m.TrustedProxyCIDRs = append(m.TrustedProxyCIDRs, cfg.TrustedProxyCIDRs...)
	}
}

func parseGlobalVPNLessOption(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	if d.NextArg() {
		return nil, d.ArgErr()
	}

	var cfg vpnlessGlobalOptions
	for d.NextBlock(0) {
		switch d.Val() {
		case "storage_path":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.StoragePath = d.Val()
		case "pairing_path":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.PairingPath = d.Val()
		case "approval_path":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.ApprovalPath = d.Val()
		case "cookie_name":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.CookieName = d.Val()
		case "cookie_domain":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.CookieDomain = d.Val()
		case "admin_host":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.AdminHost = d.Val()
		case "approval_basic_auth":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.ApprovalBasicAuth = d.Val()
		case "admin_trust_duration":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.AdminTrustDuration = d.Val()
		case "docker_host":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.DockerHost = d.Val()
		case "trusted_proxy":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.ArgErr()
			}
			cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, args...)
		default:
			return nil, d.Errf("unknown vpnless global option: %s", d.Val())
		}
	}

	return cfg, nil
}

// DeviceAuth is the Caddy middleware: Ed25519 devices, TOFU pairing, session HMAC / cookie / signed headers.
type DeviceAuth struct {
	// StoragePath is the path to the SQLite database file (WAL mode) for authorized and pending devices.
	StoragePath string `json:"storage_path,omitempty"`

	// PairingPath is the URL path for the device pairing page (default: "/vpnless/pair")
	PairingPath string `json:"pairing_path,omitempty"`

	// ApprovalPath is the URL path for the approval UI/API (default: "/vpnless/admin")
	ApprovalPath string `json:"approval_path,omitempty"`

	// CookieName is the name of the authentication cookie (default: "device_auth_token")
	CookieName string `json:"cookie_name,omitempty"`

	// CookieDomain overrides cookie Domain. If empty, it's auto-derived from request host:
	// - foo.example.com => example.com
	// - example.com => example.com
	// - localhost/IP => host-only cookie (no Domain attribute)
	CookieDomain string `json:"cookie_domain,omitempty"`

	// AdminHost is the canonical hostname for the pairing page and approval UI/API (no scheme, no path).
	// When set and the request Host differs, those routes redirect here so one origin (e.g. vpnless.site)
	// owns admin flows while other sites still run device_auth for /vpnless-client-auth.js and protected apps.
	// On this host only, GET/HEAD / redirects to ApprovalPath so a bare admin vhost needs no Caddy redir.
	// Set to "off" (or omit) to disable redirects and serve admin on each virtual host as today.
	AdminHost string `json:"admin_host,omitempty"`

	// ApprovalBasicAuth is admin login credentials in "username:password" format.
	ApprovalBasicAuth string `json:"approval_basic_auth,omitempty"`
	// AdminTrustDuration controls how long a successful admin login trusts client IP (e.g. "12h").
	AdminTrustDuration string `json:"admin_trust_duration,omitempty"`

	// ApprovalIPWhitelist is a list of IP addresses allowed to access the approval endpoint
	ApprovalIPWhitelist []string `json:"approval_ip_whitelist,omitempty"`

	// RateLimitPairing limits requests to pairing page and API (e.g. "20/1m"). Use "off" to disable.
	RateLimitPairing string `json:"rate_limit_pairing,omitempty"`
	// RateLimitApproval limits requests to approval endpoints (e.g. "10/1m"). Use "off" to disable.
	RateLimitApproval string `json:"rate_limit_approval,omitempty"`

	// DockerHost is the Docker Engine address for the admin Apps page (e.g. unix:///var/run/docker.sock).
	// Empty uses the Docker client default (DOCKER_HOST or OS default socket).
	DockerHost string `json:"docker_host,omitempty"`

	// TrustedProxyCIDRs controls trust in Forwarded / X-Forwarded-For / X-Real-IP.
	// Empty (default): headers are always honored (legacy; clients can spoof if nothing strips headers).
	// Non-empty: those headers are used only when the TCP peer (r.RemoteAddr) matches a listed CIDR
	// (e.g. your reverse proxy). Use single IPs as /32 or /128, or real prefixes like 10.0.0.0/8.
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty"`

	store  *DeviceStore
	logger *zap.Logger
	mu     sync.RWMutex

	pairingRateLimit   *rateLimitStore
	approvalRateLimit  *rateLimitStore
	adminLoginAttempts map[string]*adminLoginAttemptState
	adminSessions      map[string]time.Time
	trustedAdminIPs    map[string]time.Time
	adminTrustTTL      time.Duration

	// torture records tarpit / honeypot / slop transcripts (in-memory; per-worker if multiple Caddy workers).
	torture *tortureChamber

	// trustedProxyNets is derived from TrustedProxyCIDRs in Provision (not JSON).
	trustedProxyNets []*net.IPNet

	caddyCtx caddy.Context
}

type adminLoginAttemptState struct {
	WindowStart   time.Time
	EarlyFailures int
	HourStart     time.Time
	HourFailures  int
	CooldownUntil time.Time
}

const (
	adminLoginEarlyWindow       = 10 * time.Minute
	adminLoginEarlyBudget       = 30
	adminLoginSlowWindow        = 1 * time.Hour
	adminLoginSlowBudget        = 8
	adminLoginCooldownOnExhaust = 15 * time.Minute
)

func parseTrustedProxyCIDRs(ss []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		cidr := s
		if !strings.Contains(cidr, "/") {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("trusted_proxy: invalid IP %q", s)
			}
			if ip.To4() != nil {
				cidr = ip.String() + "/32"
			} else {
				cidr = ip.String() + "/128"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxy: %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func ipMatchesTrustedProxyNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil || len(nets) == 0 {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the canonical client IP for threat / rate-limit / pairing attribution.
func (m *DeviceAuth) clientIP(r *http.Request) string {
	peer := peerHostFromRemoteAddr(r.RemoteAddr)
	trustHeaders := len(m.trustedProxyNets) == 0
	if !trustHeaders {
		if peerIP := net.ParseIP(peer); peerIP != nil && ipMatchesTrustedProxyNets(peerIP, m.trustedProxyNets) {
			trustHeaders = true
		}
	}
	raw := ""
	if trustHeaders {
		raw = forwardedHeaderClientIP(r)
	}
	if raw == "" {
		raw = peer
	}
	return devicestore.NormalizeThreatIP(raw)
}

// CaddyModule registers this handler as `http.handlers.vpnless`.
func (DeviceAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vpnless",
		New: func() caddy.Module { return new(DeviceAuth) },
	}
}

// Provision opens storage, rate limiters, defaults.
func (m *DeviceAuth) Provision(ctx caddy.Context) error {
	m.caddyCtx = ctx
	m.logger = ctx.Logger(m)

	// Set defaults
	if m.StoragePath == "" {
		m.StoragePath = "./vpnless.db"
	}
	if m.ApprovalPath == "" {
		m.ApprovalPath = "/vpnless/admin"
	}
	if m.PairingPath == "" {
		m.PairingPath = "/vpnless/pair"
	}
	if m.CookieName == "" {
		m.CookieName = "device_auth_token"
	}
	if m.AdminTrustDuration == "" {
		m.AdminTrustDuration = "12h"
	}

	if abs, err := filepath.Abs(m.StoragePath); err == nil {
		m.StoragePath = abs
	}

	store, err := NewDeviceStore(m.StoragePath)
	if err != nil {
		return fmt.Errorf("open device store: %w", err)
	}
	m.store = store
	if _, loaded := loggedDeviceStorePaths.LoadOrStore(m.StoragePath, struct{}{}); !loaded {
		m.logger.Info("device auth store ready", zap.String("storage_path", m.StoragePath))
	}

	// Set up rate limiters (defaults: 20/min pairing, 10/min approval)
	if m.RateLimitPairing == "" {
		m.RateLimitPairing = "20/1m"
	}
	if m.RateLimitApproval == "" {
		m.RateLimitApproval = "10/1m"
	}
	if events, interval, _ := parseRateLimit(m.RateLimitPairing); events > 0 {
		m.pairingRateLimit = newRateLimitStore(events, interval)
	}
	if events, interval, _ := parseRateLimit(m.RateLimitApproval); events > 0 {
		m.approvalRateLimit = newRateLimitStore(events, interval)
	}
	if d, err := time.ParseDuration(strings.TrimSpace(m.AdminTrustDuration)); err == nil && d > 0 {
		m.adminTrustTTL = d
	} else {
		m.adminTrustTTL = 12 * time.Hour
	}
	m.adminSessions = make(map[string]time.Time)
	m.trustedAdminIPs = make(map[string]time.Time)
	m.adminLoginAttempts = make(map[string]*adminLoginAttemptState)
	m.torture = newTortureChamber(tortureMaxSessions)

	nets, err := parseTrustedProxyCIDRs(m.TrustedProxyCIDRs)
	if err != nil {
		return err
	}
	m.trustedProxyNets = nets

	m.AdminHost = normalizeAdminHostInput(m.AdminHost)

	return nil
}

// Validate is a stub today (always OK).
func (m *DeviceAuth) Validate() error {
	return nil
}

func normalizeAdminHostInput(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" || s == "off" || s == "false" || s == "disabled" || s == "no" || s == "-" {
		return ""
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(strings.TrimSuffix(s, "."), "[]")
}

func hostOnlyFromRequest(r *http.Request) string {
	h := strings.TrimSpace(strings.ToLower(r.Host))
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}

func hostsEqualCanon(a, b string) bool {
	a = strings.Trim(strings.TrimSuffix(strings.TrimSpace(strings.ToLower(a)), "."), "[]")
	b = strings.Trim(strings.TrimSuffix(strings.TrimSpace(strings.ToLower(b)), "."), "[]")
	return a != "" && b != "" && a == b
}

func (m *DeviceAuth) requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// isApprovalUIOrAPIPath is true for the approval dashboard and its API (not pairing).
func (m *DeviceAuth) isApprovalUIOrAPIPath(urlPath string) bool {
	apPath := normalizeAdminPath(urlPath)
	if apPath == m.ApprovalPath ||
		apPath == m.ApprovalPath+"/overview" ||
		apPath == m.ApprovalPath+"/devices" ||
		apPath == m.ApprovalPath+"/threats" ||
		apPath == m.ApprovalPath+"/apps" ||
		apPath == m.ApprovalPath+"/certificates" ||
		apPath == m.ApprovalPath+"/torture" ||
		apPath == m.ApprovalPath+"/pending" ||
		apPath == m.ApprovalPath+"/approve" {
		return true
	}
	return strings.HasPrefix(apPath, m.ApprovalPath+"/api/")
}

// isPairingOrApprovalPath is true for the pairing page/API and all approval UI/API routes (canonical-host redirect).
func (m *DeviceAuth) isPairingOrApprovalPath(urlPath string) bool {
	if urlPath == m.PairingPath || urlPath == m.PairingPath+"/api" {
		return true
	}
	return m.isApprovalUIOrAPIPath(urlPath)
}

func (m *DeviceAuth) shouldRedirectToAdminHost(r *http.Request) bool {
	if m.AdminHost == "" {
		return false
	}
	if hostsEqualCanon(hostOnlyFromRequest(r), m.AdminHost) {
		return false
	}
	return m.isPairingOrApprovalPath(r.URL.Path)
}

func (m *DeviceAuth) absoluteURLOnAdminHost(r *http.Request, pathAndQuery string) string {
	scheme := "http"
	if m.requestIsHTTPS(r) {
		scheme = "https"
	}
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	if pathAndQuery[0] != '/' {
		pathAndQuery = "/" + pathAndQuery
	}
	return scheme + "://" + m.AdminHost + pathAndQuery
}

func (m *DeviceAuth) pairingRedirectTarget(r *http.Request) string {
	if m.AdminHost == "" || hostsEqualCanon(hostOnlyFromRequest(r), m.AdminHost) {
		return m.PairingPath
	}
	return m.absoluteURLOnAdminHost(r, m.PairingPath)
}

// redirectAdminHostRootToApproval sends GET/HEAD / on the canonical admin_host to ApprovalPath.
func (m *DeviceAuth) redirectAdminHostRootToApproval(w http.ResponseWriter, r *http.Request) bool {
	if m.AdminHost == "" {
		return false
	}
	if !hostsEqualCanon(hostOnlyFromRequest(r), m.AdminHost) {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if normalizeAdminPath(r.URL.Path) != "/" {
		return false
	}
	http.Redirect(w, r, m.ApprovalPath, http.StatusTemporaryRedirect)
	return true
}

// cookieDomainForRequest returns the configured cookie_domain override, or an inferred parent domain.
func (m *DeviceAuth) cookieDomainForRequest(r *http.Request) string {
	if d := strings.Trim(strings.TrimSpace(strings.ToLower(m.CookieDomain)), "."); d != "" {
		return d
	}

	host := strings.TrimSpace(strings.ToLower(r.Host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSuffix(host, "."), "[]")
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return ""
	}

	labels := strings.Split(host, ".")
	switch {
	case len(labels) <= 1:
		return ""
	case len(labels) == 2:
		return host
	default:
		return strings.Join(labels[1:], ".")
	}
}

// ServeHTTP: static assets, pairing/admin, then require auth for everything else.
func (m *DeviceAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	isAuthenticated := m.isAuthenticatedRequest(r)

	// Public static assets used by VPNLess UI pages.
	if r.URL.Path == "/vpnless-icon.svg" || r.URL.Path == "/vpnless/icon.svg" {
		w.Header().Set(HeaderVPNLess, HeaderVPNLessValue)
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, vpnlessIconSVG)
		return nil
	}
	if r.URL.Path == "/vpnless-client-auth.js" {
		w.Header().Set(HeaderVPNLess, HeaderVPNLessValue)
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, vpnlessClientAuthJS)
		return nil
	}

	if m.shouldRedirectToAdminHost(r) {
		http.Redirect(w, r, m.absoluteURLOnAdminHost(r, r.URL.RequestURI()), http.StatusTemporaryRedirect)
		return nil
	}

	// Dedicated admin vhost: GET / → approval UI (no extra redir directive in Caddyfile).
	if m.redirectAdminHostRootToApproval(w, r) {
		return nil
	}

	// Handle approval UI and API endpoints.
	apPath := normalizeAdminPath(r.URL.Path)
	if m.isApprovalUIOrAPIPath(r.URL.Path) {
		ip := m.clientIP(r)
		// Logged-in admins poll these APIs; count them as authenticated for rate limits even if
		// trusted-IP grace expired or device session is absent.
		if !isAuthenticated && !m.isTrustedAdminIP(ip) && !m.adminSessionValid(r) && m.approvalRateLimit != nil && !m.approvalRateLimit.allow(ip) {
			if apPath == m.ApprovalPath+"/api/login" {
				emitAdminLoginFailure(false, "approval_rate_limit", ip, "", fmt.Sprintf("method=%s path=%s", r.Method, r.URL.Path), nil,
					zap.String("method", r.Method), zap.String("path", r.URL.Path))
			} else {
				m.logger.Warn("blocked request",
					zap.String("reason", "approval_rate_limit"),
					zap.String("client_ip", ip),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path))
			}
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return nil
		}
		m.handleApprovalAPI(w, r)
		return nil
	}

	// Handle pairing page and API
	if r.URL.Path == m.PairingPath {
		if !isAuthenticated && m.pairingRateLimit != nil && !m.pairingRateLimit.allow(m.clientIP(r)) {
			m.logger.Warn("blocked request",
				zap.String("reason", "pairing_page_rate_limit"),
				zap.String("client_ip", m.clientIP(r)),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return nil
		}
		m.handlePairingPage(w, r)
		return nil
	}
	if r.URL.Path == m.PairingPath+"/api" {
		if !isAuthenticated && m.pairingRateLimit != nil && !m.pairingRateLimit.allow(m.clientIP(r)) {
			m.logger.Warn("blocked request",
				zap.String("reason", "pairing_api_rate_limit"),
				zap.String("client_ip", m.clientIP(r)),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path))
			pairingWriteJSONError(w, http.StatusTooManyRequests, "Too many pairing requests. Please wait a moment and try again.")
			return nil
		}
		return m.handlePairingAPI(w, r)
	}

	// Check for device authentication
	authenticated, err := m.checkAuthentication(w, r)
	if err != nil {
		m.logger.Error("authentication check failed", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}

	if !authenticated {
		ip := m.clientIP(r)
		m.recordUnauthorizedAttempt(ip, r.URL.Path)
		handled, err := m.applyThreatPolicy(w, r, ip)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
		// Redirect to pairing page (absolute URL when admin_host canonicalizes pairing off-vhost).
		http.Redirect(w, r, m.pairingRedirectTarget(r), http.StatusTemporaryRedirect)
		return nil
	}

	// Device is authenticated, continue to next handler
	return next.ServeHTTP(w, r)
}

// HTTP headers for session HMAC auth (secret never sent; only proof + timestamp).
const (
	HeaderSessionProof     = "X-Session-Proof"
	HeaderSessionTimestamp = "X-Session-Timestamp"
	HeaderDevicePublicKey  = "X-Device-Public-Key"
	HeaderDeviceSig        = "X-Device-Sig"
	HeaderDeviceTimestamp  = "X-Device-Timestamp"
)

// Response header on VPNLess-served resources so clients can probe (e.g. GET /vpnless-client-auth.js).
const (
	HeaderVPNLess      = "X-VPNless"
	HeaderVPNLessValue = "1"
)

// checkAuthentication: session HMAC first, then device cookie, then Ed25519 headers (may add pending).
func (m *DeviceAuth) checkAuthentication(w http.ResponseWriter, r *http.Request) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pubKey := r.Header.Get(HeaderDevicePublicKey)
	sessionProof := r.Header.Get(HeaderSessionProof)
	sessionTS := r.Header.Get(HeaderSessionTimestamp)

	// 1) Session secret proof: HMAC-SHA256(secret, "v1|"+timestamp) — secret never on the wire
	if pubKey != "" && sessionProof != "" && sessionTS != "" {
		secret := m.store.SessionSecretForPublicKey(pubKey)
		if secret != "" && VerifySessionProof(secret, sessionTS, sessionProof, time.Now(), DefaultSessionProofSkew) {
			if m.store.IsAuthorized(pubKey) {
				m.store.TouchAuthorizedAuth(pubKey, devicestore.AuthTouchSessionProof)
				return true, nil
			}
			return false, nil
		}
	}

	// 2) Cookie fallback when JS cannot attach headers (e.g. full page navigation)
	cookie, err := r.Cookie(m.CookieName)
	if err == nil && cookie != nil {
		if m.store.IsTokenAuthorized(cookie.Value) {
			if pk, ok := devicestore.PublicKeyFromDeviceToken(cookie.Value); ok {
				m.store.TouchAuthorizedAuth(pk, devicestore.AuthTouchCookie)
			}
			return true, nil
		}
	}

	// 3) Ed25519 header-based authentication (API clients)
	signature := r.Header.Get(HeaderDeviceSig)
	timestamp := r.Header.Get(HeaderDeviceTimestamp)

	if pubKey == "" || signature == "" {
		return false, nil
	}

	// Verify signature
	if !m.verifySignature(pubKey, signature, timestamp) {
		m.logger.Debug("signature verification failed",
			zap.String("pubkey", pubKey[:16]+"..."))
		return false, nil
	}

	// Check if key is authorized
	if m.store.IsAuthorized(pubKey) {
		m.store.TouchAuthorizedAuth(pubKey, devicestore.AuthTouchSignature)
		return true, nil
	}

	// Key is valid but not authorized - add to pending
	deviceID := m.computeDeviceID(pubKey)
	if !m.store.IsPending(pubKey) {
		m.mu.RUnlock()
		m.mu.Lock()
		err := m.store.ApplyTransactional(func(work *DeviceStore) error {
			if work.IsPending(pubKey) || work.IsAuthorized(pubKey) {
				return nil
			}
			work.AddPending(pubKey, deviceID, m.clientIP(r), nil)
			return nil
		})
		m.mu.Unlock()
		if err != nil {
			m.logger.Error("failed to persist pending device", zap.Error(err))
		} else {
			m.logger.Info("new pending device detected",
				zap.String("device_id", deviceID),
				zap.String("pubkey", pubKey[:16]+"..."),
				zap.String("remote_addr", m.clientIP(r)))
		}
		m.mu.RLock()
	}

	return false, nil
}

// isAuthenticatedRequest: same auth order as checkAuthentication but read-only (no pending insert).
func (m *DeviceAuth) isAuthenticatedRequest(r *http.Request) bool {
	pubKey := r.Header.Get(HeaderDevicePublicKey)
	sessionProof := r.Header.Get(HeaderSessionProof)
	sessionTS := r.Header.Get(HeaderSessionTimestamp)

	if pubKey != "" && sessionProof != "" && sessionTS != "" {
		secret := m.store.SessionSecretForPublicKey(pubKey)
		if secret != "" && VerifySessionProof(secret, sessionTS, sessionProof, time.Now(), DefaultSessionProofSkew) && m.store.IsAuthorized(pubKey) {
			m.store.TouchAuthorizedAuth(pubKey, devicestore.AuthTouchSessionProof)
			return true
		}
	}

	cookie, err := r.Cookie(m.CookieName)
	if err == nil && cookie != nil && m.store.IsTokenAuthorized(cookie.Value) {
		if pk, ok := devicestore.PublicKeyFromDeviceToken(cookie.Value); ok {
			m.store.TouchAuthorizedAuth(pk, devicestore.AuthTouchCookie)
		}
		return true
	}

	signature := r.Header.Get(HeaderDeviceSig)
	timestamp := r.Header.Get(HeaderDeviceTimestamp)
	if pubKey == "" || signature == "" {
		return false
	}
	if !m.verifySignature(pubKey, signature, timestamp) {
		return false
	}
	if m.store.IsAuthorized(pubKey) {
		m.store.TouchAuthorizedAuth(pubKey, devicestore.AuthTouchSignature)
		return true
	}
	return false
}

func (m *DeviceAuth) verifySignature(pubKeyB64, sigB64, timestamp string) bool {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return false
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}

	// Create message: timestamp or current time if not provided
	message := timestamp
	if message == "" {
		message = fmt.Sprintf("%d", time.Now().Unix())
	}

	return ed25519.Verify(pubKeyBytes, []byte(message), sigBytes)
}

// parsePairingPublicKeyQuery validates a base64 Ed25519 public key from a query parameter (used to block banned devices from loading the full pairing UI).
func parsePairingPublicKeyQuery(q string) (pubKey string, ok bool) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(q)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return "", false
	}
	return q, true
}

func (m *DeviceAuth) handlePairingPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if pk, ok := parsePairingPublicKeyQuery(r.URL.Query().Get("public_key")); ok {
		m.mu.RLock()
		blocked := m.store.PairingPermanentlyBlocked(pk)
		m.mu.RUnlock()
		if blocked {
			w.Header().Set(HeaderVPNLess, HeaderVPNLessValue)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, pairingBannedPageHTML)
			return
		}
	}

	clientInfo := getClientInfoFromRequest(m.clientIP(r), r.UserAgent())
	clientInfoJSON, _ := json.Marshal(clientInfo)

	html := pairingPageHTML
	const placeholder = "window.__SERVER_CLIENT_INFO__=null;"
	html = strings.Replace(html, placeholder, "window.__SERVER_CLIENT_INFO__="+string(clientInfoJSON)+";", 1)
	html = strings.ReplaceAll(html, "__VPNLESS_PAIRING_API_PATH__", m.PairingPath+"/api")

	w.Header().Set(HeaderVPNLess, HeaderVPNLessValue)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, html)
}

// normalizeAdminPath trims one trailing slash (except root) so /vpnless/admin/api/login/ still matches handlers.
func normalizeAdminPath(p string) string {
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		return strings.TrimSuffix(p, "/")
	}
	return p
}

// emitAdminLoginFailure writes a plain line to stderr (always visible in tmux / foreground)
// and to Caddy's default logger at info/error. Use this because zap output can be filtered
// by log level (e.g. only ERROR) or by logger name, and does not always mirror stderr.
func emitAdminLoginFailure(asError bool, reason, ip, user, stderrExtra string, err error, fields ...zap.Field) {
	line := fmt.Sprintf("vpnless/admin: login FAILED reason=%s client_ip=%s", reason, ip)
	if user != "" {
		line += fmt.Sprintf(" username=%q", user)
	}
	if stderrExtra != "" {
		line += " " + stderrExtra
	}
	if err != nil {
		line += fmt.Sprintf(" err=%v", err)
	}
	_, _ = fmt.Fprintln(os.Stderr, line)
	base := []zap.Field{zap.String("reason", reason), zap.String("client_ip", ip)}
	base = append(base, fields...)
	if user != "" {
		base = append(base, zap.String("username", user))
	}
	if err != nil {
		base = append(base, zap.Error(err))
	}
	if asError {
		caddy.Log().Error("admin login failed", base...)
	} else {
		caddy.Log().Info("admin login failed", base...)
	}
}

func (m *DeviceAuth) handleApprovalAPI(w http.ResponseWriter, r *http.Request) {
	switch normalizeAdminPath(r.URL.Path) {
	case m.ApprovalPath, m.ApprovalPath + "/overview":
		m.serveAdminDashboard(w, r, "overview")
	case m.ApprovalPath + "/devices":
		m.serveAdminDashboard(w, r, "devices")
	case m.ApprovalPath + "/threats":
		m.serveAdminDashboard(w, r, "threats")
	case m.ApprovalPath + "/apps":
		m.serveAdminDashboard(w, r, "apps")
	case m.ApprovalPath + "/certificates":
		m.serveAdminDashboard(w, r, "certificates")
	case m.ApprovalPath + "/torture":
		m.serveAdminDashboard(w, r, "torture")
	case m.ApprovalPath + "/api/login":
		m.handleAdminLogin(w, r)
	case m.ApprovalPath + "/api/logout":
		m.handleAdminLogout(w, r)
	case m.ApprovalPath + "/api/status":
		m.handleAdminStatus(w, r)
	case m.ApprovalPath + "/api/otp/enable":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleAdminOTPEnable(w, r)
	case m.ApprovalPath + "/api/pending":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handlePendingList(w, r)
	case m.ApprovalPath + "/pending": // legacy path alias
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handlePendingList(w, r)
	case m.ApprovalPath + "/api/approve":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleApprove(w, r)
	case m.ApprovalPath + "/api/deny":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleDeny(w, r)
	case m.ApprovalPath + "/api/pending/display_name":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handlePendingDisplayName(w, r)
	case m.ApprovalPath + "/api/authorized":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleAuthorizedList(w, r)
	case m.ApprovalPath + "/api/authorized/revoke":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleAuthorizedRevoke(w, r)
	case m.ApprovalPath + "/api/authorized/display_name":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleAuthorizedDisplayName(w, r)
	case m.ApprovalPath + "/api/threats":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleThreatList(w, r)
	case m.ApprovalPath + "/api/threats/action":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleThreatAction(w, r)
	case m.ApprovalPath + "/api/certificates":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleCertificatesList(w, r)
	case m.ApprovalPath + "/api/apps":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleAppsList(w, r)
	case m.ApprovalPath + "/api/overview":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleOverview(w, r)
	case m.ApprovalPath + "/api/denied":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleDeniedList(w, r)
	case m.ApprovalPath + "/api/denied/remove":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleDeniedRemove(w, r)
	case m.ApprovalPath + "/api/activity":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleActivityList(w, r)
	case m.ApprovalPath + "/api/torture/stream":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleTortureStream(w, r)
	case m.ApprovalPath + "/api/torture":
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleTortureList(w, r)
	case m.ApprovalPath + "/approve": // legacy path alias
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleApprove(w, r)
	case m.ApprovalPath + "/deny": // legacy path alias
		if !m.requireAdminSession(w, r) {
			return
		}
		m.handleDeny(w, r)
	default:
		if strings.HasPrefix(normalizeAdminPath(r.URL.Path), m.ApprovalPath+"/api/") {
			_, _ = fmt.Fprintf(os.Stderr, "vpnless/admin: no handler for %s %s (check trailing slash / wrong approval_path)\n", r.Method, r.URL.Path)
			caddy.Log().Warn("admin api no matching route", zap.String("method", r.Method), zap.String("path", r.URL.Path))
		}
		http.NotFound(w, r)
	}
}

func (m *DeviceAuth) checkApprovalCredentials(username, password string) bool {
	if m.ApprovalBasicAuth == "" {
		return true
	}
	return fmt.Sprintf("%s:%s", username, password) == m.ApprovalBasicAuth
}

// checkApprovalAccess: IP allowlist / trusted-admin shortcuts before basic auth.
func (m *DeviceAuth) checkApprovalAccess(r *http.Request) bool {
	if m.isTrustedAdminIP(m.clientIP(r)) {
		return true
	}
	if len(m.ApprovalIPWhitelist) > 0 {
		remote := m.clientIP(r)
		for _, allowedIP := range m.ApprovalIPWhitelist {
			allowedIP = strings.TrimSpace(allowedIP)
			if allowedIP == "" {
				continue
			}
			if approvalIPAllowed(remote, allowedIP) {
				return true
			}
		}
		return false
	}
	return true
}

func approvalIPAllowed(remote, allowed string) bool {
	if remote == allowed {
		return true
	}
	if h, _, err := net.SplitHostPort(allowed); err == nil && h == remote {
		return true
	}
	return false
}

func writeAdminJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(v)
}

func (m *DeviceAuth) handlePendingList(w http.ResponseWriter, r *http.Request) {
	if err := m.store.Load(); err != nil {
		m.logger.Error("failed to reload device store", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pending := m.store.GetPending()
	writeAdminJSON(w, pending)
}

type authorizedDeviceAdminJSON struct {
	PublicKey            string                         `json:"public_key"`
	DeviceID             string                         `json:"device_id"`
	ApprovedAt           time.Time                      `json:"approved_at"`
	RemoteAddr           string                         `json:"remote_addr,omitempty"`
	LastSeen             *time.Time                     `json:"last_seen,omitempty"`
	LastSeenSessionProof *time.Time                     `json:"last_seen_session_proof,omitempty"`
	LastSeenCookie       *time.Time                     `json:"last_seen_cookie,omitempty"`
	ClientInfo           *devicestore.PendingClientInfo `json:"client_info,omitempty"`
}

// handleAuthorizedList: same as DB list but strips session secrets for JSON responses.
func (m *DeviceAuth) handleAuthorizedList(w http.ResponseWriter, r *http.Request) {
	if err := m.store.Load(); err != nil {
		m.logger.Error("failed to reload device store", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	list, err := m.store.GetAuthorized()
	if err != nil {
		m.logger.Error("failed to list authorized devices", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	out := make([]authorizedDeviceAdminJSON, 0, len(list))
	for _, d := range list {
		row := authorizedDeviceAdminJSON{
			PublicKey:  d.PublicKey,
			DeviceID:   d.DeviceID,
			ApprovedAt: d.ApprovedAt,
			RemoteAddr: d.RemoteAddr,
			ClientInfo: d.ClientInfo,
		}
		if !d.LastSeen.IsZero() {
			t := d.LastSeen
			row.LastSeen = &t
		}
		if !d.LastSeenSessionProof.IsZero() {
			t := d.LastSeenSessionProof
			row.LastSeenSessionProof = &t
		}
		if !d.LastSeenCookie.IsZero() {
			t := d.LastSeenCookie
			row.LastSeenCookie = &t
		}
		out = append(out, row)
	}
	writeAdminJSON(w, out)
}

func (m *DeviceAuth) handleAuthorizedRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
		DeviceID  string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.PublicKey)
	if key == "" {
		key = strings.TrimSpace(req.DeviceID)
	}
	if key == "" {
		http.Error(w, "public_key or device_id is required", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.store.ApplyTransactional(func(work *DeviceStore) error {
		if !work.RemoveAuthorizedDevice(key) {
			return errAuthorizedDeviceNotFound
		}
		return nil
	})
	if errors.Is(err, errAuthorizedDeviceNotFound) {
		http.Error(w, "Device not found in authorized list", http.StatusNotFound)
		return
	}
	if err != nil {
		m.logger.Error("failed to revoke authorized device", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	m.logger.Info("authorized device revoked", zap.String("key", key[:min(16, len(key))]+"..."))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func (m *DeviceAuth) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PublicKey string `json:"public_key"`
		DeviceID  string `json:"device_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	err := m.store.ApplyTransactional(func(work *DeviceStore) error {
		if !work.ApproveDevice(req.PublicKey, req.DeviceID) {
			return ErrPendingDeviceNotFound
		}
		return nil
	})
	if errors.Is(err, ErrPendingDeviceNotFound) {
		http.Error(w, "Device not found in pending list", http.StatusNotFound)
		return
	}
	if err != nil {
		m.logger.Error("failed to save device store", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	m.logger.Info("device approved",
		zap.String("device_id", req.DeviceID),
		zap.String("pubkey", req.PublicKey[:16]+"..."))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
}

func (m *DeviceAuth) handleDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicKey   string `json:"public_key"`
		DeviceID    string `json:"device_id"`
		DenyMessage string `json:"deny_message"`
		SnarkIndex  *int   `json:"snark_index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.PublicKey)
	if key == "" {
		key = strings.TrimSpace(req.DeviceID)
	}
	if key == "" {
		http.Error(w, "public_key or device_id is required", http.StatusBadRequest)
		return
	}
	custom := SanitizeDenyMessage(req.DenyMessage)
	var snPtr *int
	if req.SnarkIndex != nil {
		if *req.SnarkIndex < 0 || *req.SnarkIndex > devicestore.MaxPairingSnarkIndex {
			http.Error(w, "invalid snark_index", http.StatusBadRequest)
			return
		}
		v := *req.SnarkIndex
		snPtr = &v
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.store.DenyPendingDevice(key, custom, snPtr)
	if errors.Is(err, ErrPendingDeviceNotFound) {
		http.Error(w, "Device not found in pending list", http.StatusNotFound)
		return
	}
	if err != nil {
		m.logger.Error("failed to deny pending device", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "denied"})
}

func (m *DeviceAuth) handlePendingDisplayName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicKey   string `json:"public_key"`
		DeviceID    string `json:"device_id"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.PublicKey)
	if key == "" {
		key = strings.TrimSpace(req.DeviceID)
	}
	if key == "" {
		http.Error(w, "public_key or device_id is required", http.StatusBadRequest)
		return
	}
	name := SanitizeDisplayName(req.DisplayName)
	m.mu.Lock()
	defer m.mu.Unlock()
	var ok bool
	err := m.store.ApplyTransactional(func(work *DeviceStore) error {
		ok = work.UpdatePendingDisplayName(key, name)
		return nil
	})
	if err != nil {
		m.logger.Error("failed to update pending display name", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Device not found in pending list", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "display_name": name})
}

func (m *DeviceAuth) handleAuthorizedDisplayName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicKey   string `json:"public_key"`
		DeviceID    string `json:"device_id"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.PublicKey)
	if key == "" {
		key = strings.TrimSpace(req.DeviceID)
	}
	if key == "" {
		http.Error(w, "public_key or device_id is required", http.StatusBadRequest)
		return
	}
	name := SanitizeDisplayName(req.DisplayName)
	m.mu.Lock()
	defer m.mu.Unlock()
	var ok bool
	err := m.store.ApplyTransactional(func(work *DeviceStore) error {
		ok = work.UpdateAuthorizedDisplayName(key, name)
		return nil
	})
	if err != nil {
		m.logger.Error("failed to update authorized display name", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Device not found in authorized list", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "display_name": name})
}

func (m *DeviceAuth) serveAdminDashboard(w http.ResponseWriter, r *http.Request, initialTab string) {
	switch initialTab {
	case "overview", "devices", "threats", "apps", "certificates", "torture":
	default:
		initialTab = "overview"
	}
	html := strings.ReplaceAll(approvalDashboardHTML, "__VPNLESS_APPROVAL_BASE__", m.ApprovalPath)
	html = strings.ReplaceAll(html, "__VPNLESS_INITIAL_TAB_JS__", strconv.Quote(initialTab))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, html)
}

const adminSessionCookieName = "vpnless_admin_session"

// adminSessionValid is true when the request has an active admin session cookie (only meaningful if admin login is configured).
func (m *DeviceAuth) adminSessionValid(r *http.Request) bool {
	if strings.TrimSpace(m.ApprovalBasicAuth) == "" {
		return false
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil || cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	exp, ok := m.adminSessions[cookie.Value]
	return ok && time.Now().Before(exp)
}

func (m *DeviceAuth) requireAdminSession(w http.ResponseWriter, r *http.Request) bool {
	if !m.checkApprovalAccess(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	if strings.TrimSpace(m.ApprovalBasicAuth) == "" {
		return true
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil || cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.adminSessions[cookie.Value]
	if !ok || time.Now().After(exp) {
		delete(m.adminSessions, cookie.Value)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (m *DeviceAuth) setAdminSession(w http.ResponseWriter, r *http.Request) error {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	m.mu.Lock()
	m.adminSessions[token] = time.Now().Add(12 * time.Hour)
	m.trustedAdminIPs[m.clientIP(r)] = time.Now().Add(m.adminTrustTTL)
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    token,
		Path:     m.ApprovalPath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (m *DeviceAuth) isTrustedAdminIP(ip string) bool {
	if strings.TrimSpace(ip) == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.trustedAdminIPs[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(m.trustedAdminIPs, ip)
		return false
	}
	return true
}

func (m *DeviceAuth) clearAdminSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(adminSessionCookieName); err == nil && cookie != nil {
		m.mu.Lock()
		delete(m.adminSessions, cookie.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     m.ApprovalPath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (m *DeviceAuth) allowAdminLoginAttempt(ip string, now time.Time) bool {
	if strings.TrimSpace(ip) == "" {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.adminLoginAttempts[ip]
	if !ok {
		return true
	}
	if !st.CooldownUntil.IsZero() && now.Before(st.CooldownUntil) {
		return false
	}
	if st.WindowStart.IsZero() || now.Sub(st.WindowStart) > adminLoginEarlyWindow {
		return true
	}
	// First 10 minutes after first failed login: allow a larger retry burst.
	if st.EarlyFailures < adminLoginEarlyBudget {
		return true
	}
	// After early burst, enforce much slower retries in hourly windows.
	if st.HourStart.IsZero() || now.Sub(st.HourStart) > adminLoginSlowWindow {
		return true
	}
	if st.HourFailures < adminLoginSlowBudget {
		return true
	}
	return false
}

func (m *DeviceAuth) noteAdminLoginFailure(ip string, now time.Time) {
	if strings.TrimSpace(ip) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.adminLoginAttempts[ip]
	if st == nil {
		st = &adminLoginAttemptState{}
		m.adminLoginAttempts[ip] = st
	}
	if st.WindowStart.IsZero() || now.Sub(st.WindowStart) > adminLoginEarlyWindow {
		st.WindowStart = now
		st.EarlyFailures = 0
		st.HourStart = time.Time{}
		st.HourFailures = 0
		st.CooldownUntil = time.Time{}
	}
	st.EarlyFailures++
	if st.EarlyFailures <= adminLoginEarlyBudget {
		return
	}
	if st.HourStart.IsZero() || now.Sub(st.HourStart) > adminLoginSlowWindow {
		st.HourStart = now
		st.HourFailures = 0
	}
	st.HourFailures++
	if st.HourFailures >= adminLoginSlowBudget {
		st.CooldownUntil = now.Add(adminLoginCooldownOnExhaust)
	}
}

func (m *DeviceAuth) clearAdminLoginFailures(ip string) {
	if strings.TrimSpace(ip) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.adminLoginAttempts, ip)
}

func (m *DeviceAuth) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	ip := m.clientIP(r)
	if r.Method != http.MethodPost {
		emitAdminLoginFailure(false, "method_not_allowed", ip, "", fmt.Sprintf("method=%s", r.Method), nil, zap.String("method", r.Method))
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.checkApprovalAccess(r) {
		emitAdminLoginFailure(false, "approval_access_denied", ip, "", "", nil)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now()
	if !m.allowAdminLoginAttempt(ip, now) {
		emitAdminLoginFailure(false, "rate_limited", ip, "", "", nil)
		http.Error(w, "Too many login attempts right now. Please wait and try again.", http.StatusTooManyRequests)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		OTPCode  string `json:"otp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		emitAdminLoginFailure(false, "invalid_json_body", ip, "", "", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(req.Username)
	if !m.checkApprovalCredentials(user, strings.TrimSpace(req.Password)) {
		m.noteAdminLoginFailure(ip, now)
		emitAdminLoginFailure(false, "bad_credentials", ip, user, "", nil)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	settings, err := m.store.GetAdminAuthSettings()
	if err != nil {
		emitAdminLoginFailure(true, "auth_settings_store_error", ip, user, "", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// Only require TOTP when OTP is enabled *and* a secret exists. If otp_enabled was set
	// without a secret (or the DB row is inconsistent), password login still works so the
	// admin panel can recover and re-run OTP setup.
	if settings.OTPEnabled && strings.TrimSpace(settings.OTPSecret) == "" {
		m.logger.Warn("admin auth: otp_enabled is set but otp_secret is empty; allowing password-only login until OTP is configured")
	}
	otpRequired := settings.OTPEnabled && strings.TrimSpace(settings.OTPSecret) != ""
	if otpRequired && !verifyTOTP(settings.OTPSecret, req.OTPCode, time.Now()) {
		m.noteAdminLoginFailure(ip, now)
		emitAdminLoginFailure(false, "invalid_otp", ip, user, "", nil)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := m.setAdminSession(w, r); err != nil {
		emitAdminLoginFailure(true, "session_cookie_error", ip, user, "", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	m.clearAdminLoginFailures(ip)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (m *DeviceAuth) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m.clearAdminSession(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *DeviceAuth) adminStatusPayload(r *http.Request) (map[string]any, error) {
	settings, err := m.store.GetAdminAuthSettings()
	if err != nil {
		return nil, err
	}
	authenticated := false
	if strings.TrimSpace(m.ApprovalBasicAuth) == "" {
		// Open admin (no password): treat network/IP access as signed-in so the dashboard loads and polling starts
		// without relying on a session cookie that is only issued after clicking Sign in.
		if m.checkApprovalAccess(r) {
			authenticated = true
		}
	} else if cookie, err := r.Cookie(adminSessionCookieName); err == nil && cookie != nil {
		m.mu.Lock()
		exp, ok := m.adminSessions[cookie.Value]
		if ok && time.Now().Before(exp) {
			authenticated = true
		} else if ok {
			delete(m.adminSessions, cookie.Value)
		}
		m.mu.Unlock()
	}
	loginRequiresOTP := settings.OTPEnabled && strings.TrimSpace(settings.OTPSecret) != ""
	payload := map[string]any{
		"authenticated":      authenticated,
		"otp_enabled":        settings.OTPEnabled,
		"login_requires_otp": loginRequiresOTP,
	}
	// Offer OTP setup when OTP is off, or when the DB is inconsistent (enabled flag but no secret).
	if authenticated && (!settings.OTPEnabled || strings.TrimSpace(settings.OTPSecret) == "") {
		if strings.TrimSpace(settings.OTPSecret) == "" {
			wasEnabledWithoutSecret := settings.OTPEnabled
			secret, err := generateTOTPSecret()
			if err != nil {
				return nil, err
			}
			if err := m.store.SaveAdminOTPSetup(secret, false); err != nil {
				return nil, err
			}
			settings.OTPSecret = secret
			settings.OTPEnabled = false
			if wasEnabledWithoutSecret {
				m.logger.Warn(`admin auth: otp_enabled was set without a secret; generated a new secret; complete Enable OTP again after scanning`)
			}
		}
		payload["otp_secret"] = settings.OTPSecret
		payload["otp_uri"] = "otpauth://totp/VPNLess:admin?secret=" + settings.OTPSecret + "&issuer=VPNLess"
		payload["otp_enabled"] = settings.OTPEnabled
	}
	return payload, nil
}

func (m *DeviceAuth) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if !m.checkApprovalAccess(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	payload, err := m.adminStatusPayload(r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, payload)
}

func (m *DeviceAuth) handleAdminOTPEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		OTPCode string `json:"otp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	settings, err := m.store.GetAdminAuthSettings()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(settings.OTPSecret) == "" {
		http.Error(w, "OTP secret not initialized", http.StatusBadRequest)
		return
	}
	if !verifyTOTP(settings.OTPSecret, req.OTPCode, time.Now()) {
		http.Error(w, "Invalid OTP code", http.StatusUnauthorized)
		return
	}
	if err := m.store.SaveAdminOTPSetup(settings.OTPSecret, true); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// UnmarshalCaddyfile parses `device_auth` / `vpnless` handler blocks.
func (m *DeviceAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "storage_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.StoragePath = d.Val()
			case "pairing_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.PairingPath = d.Val()
			case "approval_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ApprovalPath = d.Val()
			case "cookie_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CookieName = d.Val()
			case "cookie_domain":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CookieDomain = d.Val()
			case "admin_host":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.AdminHost = d.Val()
			case "approval_basic_auth":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ApprovalBasicAuth = d.Val()
			case "admin_trust_duration":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.AdminTrustDuration = d.Val()
			case "approval_ip_whitelist":
				args := d.RemainingArgs()
				m.ApprovalIPWhitelist = append(m.ApprovalIPWhitelist, args...)
			case "rate_limit_pairing":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RateLimitPairing = d.Val()
			case "rate_limit_approval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RateLimitApproval = d.Val()
			case "docker_host":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.DockerHost = d.Val()
			case "trusted_proxy":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.TrustedProxyCIDRs = append(m.TrustedProxyCIDRs, args...)
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func (m *DeviceAuth) Cleanup() error {
	if m.store != nil {
		err := m.store.Close()
		m.store = nil
		return err
	}
	return nil
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*DeviceAuth)(nil)
	_ caddy.Module                = (*DeviceAuth)(nil)
	_ caddy.Provisioner           = (*DeviceAuth)(nil)
	_ caddy.CleanerUpper          = (*DeviceAuth)(nil)
	_ caddy.Validator             = (*DeviceAuth)(nil)
	_ caddyfile.Unmarshaler       = (*DeviceAuth)(nil)
)
