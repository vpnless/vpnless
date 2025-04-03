package vpnless

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)


// rateLimitStore holds per-IP limiters with periodic cleanup.
type rateLimitStore struct {
	limit    rate.Limit
	burst    int
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
}

func newRateLimitStore(events int, interval time.Duration) *rateLimitStore {
	// events per interval -> rate per second
	perSecond := float64(events) / interval.Seconds()
	burst := events
	if burst < 1 {
		burst = 1
	}
	return &rateLimitStore{
		limit:  rate.Limit(perSecond),
		burst:  burst,
		limiters: make(map[string]*rate.Limiter),
	}
}

func (s *rateLimitStore) allow(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	lim, ok := s.limiters[ip]
	if !ok {
		lim = rate.NewLimiter(s.limit, s.burst)
		s.limiters[ip] = lim
	}

	return lim.Allow()
}

// parseRateLimit parses "events/duration" e.g. "20/1m", "10/1min", "5/1h".
// Returns (0, 0) for "off" or invalid, meaning no rate limit.
func parseRateLimit(s string) (events int, interval time.Duration, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "off" || s == "0" {
		return 0, 0, nil
	}

	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, nil
	}

	events, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || events <= 0 {
		return 0, 0, nil
	}

	dur := strings.TrimSpace(parts[1])
	switch {
	case strings.HasSuffix(dur, "s"):
		n, _ := strconv.Atoi(strings.TrimSuffix(dur, "s"))
		interval = time.Duration(n) * time.Second
	case strings.HasSuffix(dur, "m"), strings.HasSuffix(dur, "min"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(dur, "min"), "m"))
		interval = time.Duration(n) * time.Minute
	case strings.HasSuffix(dur, "h"):
		n, _ := strconv.Atoi(strings.TrimSuffix(dur, "h"))
		interval = time.Duration(n) * time.Hour
	default:
		return 0, 0, nil
	}

	if interval <= 0 {
		return 0, 0, nil
	}
	return events, interval, nil
}

// forwardedHeaderClientIP returns a client IP from Forwarded / X-Forwarded-For / X-Real-IP only.
// It does not consult r.RemoteAddr — pair with peerHostFromRemoteAddr for a full resolution policy.
func forwardedHeaderClientIP(r *http.Request) string {
	// 1) RFC 7239 Forwarded: for=...
	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		if ip := firstForwardedForIP(fwd); ip != "" {
			return ip
		}
	}

	// 2) De-facto standard X-Forwarded-For chain.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := firstXFFIP(xff); ip != "" {
			return ip
		}
	}

	// 3) Common single-IP header.
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		if ip := parseIPToken(xrip); ip != "" {
			return ip
		}
	}

	return ""
}

// peerHostFromRemoteAddr returns the host part of r.RemoteAddr (or the whole value if not host:port).
func peerHostFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}

func firstXFFIP(xff string) string {
	parts := strings.Split(xff, ",")
	var fallback string
	for _, p := range parts {
		ip := parseIPToken(strings.TrimSpace(p))
		if ip == "" {
			continue
		}
		if fallback == "" {
			fallback = ip
		}
		if !isLoopbackIP(ip) {
			return ip
		}
	}
	return fallback
}

func firstForwardedForIP(forwarded string) string {
	parts := strings.Split(forwarded, ",")
	var fallback string
	for _, part := range parts {
		segments := strings.Split(part, ";")
		for _, seg := range segments {
			kv := strings.SplitN(strings.TrimSpace(seg), "=", 2)
			if len(kv) != 2 || strings.ToLower(kv[0]) != "for" {
				continue
			}
			raw := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			ip := parseIPToken(raw)
			if ip == "" {
				continue
			}
			if fallback == "" {
				fallback = ip
			}
			if !isLoopbackIP(ip) {
				return ip
			}
		}
	}
	return fallback
}

func parseIPToken(token string) string {
	if token == "" {
		return ""
	}

	// Bracketed IPv6 with optional port: [2001:db8::1]:443
	if strings.HasPrefix(token, "[") {
		if i := strings.Index(token, "]"); i > 1 {
			addr := token[1:i]
			if ip := net.ParseIP(addr); ip != nil {
				return ip.String()
			}
		}
	}

	// host:port
	if h, _, err := net.SplitHostPort(token); err == nil {
		if ip := net.ParseIP(h); ip != nil {
			return ip.String()
		}
	}

	// plain IP
	if ip := net.ParseIP(token); ip != nil {
		return ip.String()
	}

	return ""
}

func isLoopbackIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}
