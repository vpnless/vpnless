package vpnless

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
)

// adminCertHostJSON is one row for the admin Certificates tab.
type adminCertHostJSON struct {
	Host   string `json:"host"`
	Status string `json:"status"` // ok | expiring_soon | expired | no_certificate | leaf_missing

	NotBefore     *time.Time `json:"not_before,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	DaysRemaining *float64   `json:"days_remaining,omitempty"`
	Issuer        string     `json:"issuer,omitempty"`
	Subjects      []string   `json:"subjects,omitempty"`

	ChallengeSummary string   `json:"challenge_summary,omitempty"`
	ChallengeModes   []string `json:"challenge_modes,omitempty"`
	IssuerModules    []string `json:"issuer_modules,omitempty"`
	OnDemandPolicy   bool     `json:"on_demand_policy,omitempty"`

	SortRank int       `json:"-"`
	SortTime time.Time `json:"-"`
}

func (m *DeviceAuth) handleCertificatesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, warn := m.collectAdminCertificates()
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].SortRank != rows[j].SortRank {
			return rows[i].SortRank < rows[j].SortRank
		}
		if !rows[i].SortTime.Equal(rows[j].SortTime) {
			return rows[i].SortTime.Before(rows[j].SortTime)
		}
		return rows[i].Host < rows[j].Host
	})
	payload := map[string]any{"certificates": rows}
	if warn != "" {
		payload["warning"] = warn
	}
	writeAdminJSON(w, payload)
}

func (m *DeviceAuth) collectAdminCertificates() ([]adminCertHostJSON, string) {
	var warning string
	if m.caddyCtx.Context == nil {
		return nil, "certificate list unavailable (server context not ready)"
	}
	httpIface, err := m.caddyCtx.App("http")
	if err != nil {
		return nil, fmt.Sprintf("certificate list unavailable: %v", err)
	}
	httpApp, ok := httpIface.(*caddyhttp.App)
	if !ok || httpApp == nil {
		return nil, "certificate list unavailable: http app has unexpected type"
	}
	tlsIface, err := m.caddyCtx.App("tls")
	if err != nil {
		warning = "tls app unavailable; challenge details may be incomplete"
	}
	tlsApp, _ := tlsIface.(*caddytls.TLS)

	hosts := collectHostsFromHTTPApp(httpApp)
	if len(hosts) == 0 {
		msg := "no host matchers found in HTTP routes (nothing to list)"
		if warning != "" {
			return []adminCertHostJSON{}, warning + "; " + msg
		}
		return []adminCertHostJSON{}, msg
	}

	repl := caddy.NewReplacer()
	now := time.Now()
	const expiringSoonDays = 14

	rows := make([]adminCertHostJSON, 0, len(hosts))
	for _, host := range hosts {
		row := adminCertHostJSON{Host: host}
		if tlsApp != nil {
			ap := automationPolicyForHost(tlsApp, host, repl)
			summary, modes, issuers, onDemand := describeAutomationPolicy(ap, tlsApp)
			row.ChallengeSummary = summary
			row.ChallengeModes = modes
			row.IssuerModules = issuers
			row.OnDemandPolicy = onDemand
		} else {
			row.ChallengeSummary = "TLS app not loaded"
		}

		certs := caddytls.AllMatchingCertificates(host)
		cert := pickPrimaryCert(certs)
		if cert.Empty() || cert.Leaf == nil {
			row.Status = "no_certificate"
			if !cert.Empty() && cert.Leaf == nil {
				row.Status = "leaf_missing"
			}
			row.SortRank = certSortRank(row.Status)
			row.SortTime = time.Time{}
			rows = append(rows, row)
			continue
		}

		leaf := cert.Leaf
		row.NotBefore = &leaf.NotBefore
		row.NotAfter = &leaf.NotAfter
		row.Issuer = certIssuerString(leaf)
		if len(cert.Names) > 0 {
			row.Subjects = append([]string(nil), cert.Names...)
		} else {
			row.Subjects = append([]string(nil), leaf.DNSNames...)
		}

		exp := utcLeafExpiresAt(leaf)
		if !exp.IsZero() {
			d := exp.Sub(now).Hours() / 24
			row.DaysRemaining = &d
		}

		switch {
		case cert.Expired():
			row.Status = "expired"
		case !exp.IsZero() && exp.Sub(now) < expiringSoonDays*24*time.Hour:
			row.Status = "expiring_soon"
		default:
			row.Status = "ok"
		}
		row.SortRank = certSortRank(row.Status)
		if !exp.IsZero() {
			row.SortTime = exp
		} else {
			row.SortTime = leaf.NotAfter
		}
		rows = append(rows, row)
	}
	return rows, warning
}

// expiresAtLeaf matches certmagic's adjusted NotAfter (1s past truncated second).
func utcLeafExpiresAt(leaf *x509.Certificate) time.Time {
	if leaf == nil {
		return time.Time{}
	}
	return leaf.NotAfter.Truncate(time.Second).Add(1 * time.Second)
}

func certSortRank(status string) int {
	switch status {
	case "no_certificate", "leaf_missing":
		return 0
	case "expired":
		return 1
	case "expiring_soon":
		return 2
	default:
		return 3
	}
}

func collectHostsFromHTTPApp(app *caddyhttp.App) []string {
	if app == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		key := strings.ToLower(h)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}

	walk := func(route caddyhttp.Route) {
		for _, ms := range route.MatcherSets {
			for _, matcher := range ms {
				hm, ok := matcher.(*caddyhttp.MatchHost)
				if !ok || hm == nil {
					continue
				}
				for _, host := range *hm {
					add(host)
				}
			}
		}
	}

	for _, srv := range app.Servers {
		for _, route := range srv.Routes {
			walk(route)
		}
		for _, route := range srv.NamedRoutes {
			if route != nil {
				walk(*route)
			}
		}
	}
	return out
}

// automationPolicyForHost mirrors caddytls.getAutomationPolicyForName using only exported fields.
func automationPolicyForHost(tlsApp *caddytls.TLS, host string, repl *caddy.Replacer) *caddytls.AutomationPolicy {
	if tlsApp == nil || tlsApp.Automation == nil {
		return nil
	}
	if repl == nil {
		repl = caddy.NewReplacer()
	}
	for _, ap := range tlsApp.Automation.Policies {
		if len(ap.SubjectsRaw) == 0 {
			return ap
		}
		for _, raw := range ap.SubjectsRaw {
			sub := repl.ReplaceAll(raw, "")
			if certmagic.MatchWildcard(host, sub) {
				return ap
			}
		}
	}
	return nil
}

func describeAutomationPolicy(ap *caddytls.AutomationPolicy, tlsApp *caddytls.TLS) (summary string, modes []string, issuerNames []string, onDemand bool) {
	if ap == nil {
		return "No explicit automation policy matched this host (Caddy default issuance may still apply).", nil, nil, false
	}
	onDemand = ap.OnDemand
	if len(ap.Issuers) == 0 {
		return "Default issuers (ACME / internal) — challenges depend on CA and global TLS options.", []string{"HTTP-01 (default)", "TLS-ALPN-01 (default)"}, nil, onDemand
	}
	var parts []string
	globalDNS := tlsApp != nil && len(tlsApp.DNSRaw) > 0
	for _, iss := range ap.Issuers {
		issuerNames = append(issuerNames, fmt.Sprintf("%T", iss))
		switch v := iss.(type) {
		case *caddytls.ACMEIssuer:
			s, m := describeACMEIssuerChallenges(v, globalDNS)
			if s != "" {
				parts = append(parts, s)
			}
			modes = append(modes, m...)
		case *caddytls.ZeroSSLIssuer:
			parts = append(parts, "ZeroSSL API (HTTP validation unless CNAME/DNS configured)")
			if v.CNAMEValidation != nil && len(v.CNAMEValidation.ProviderRaw) > 0 {
				modes = append(modes, "ZeroSSL CNAME / DNS validation")
			} else {
				modes = append(modes, "HTTP-01 (ZeroSSL)")
			}
		default:
			parts = append(parts, fmt.Sprintf("Issuer %T (see Caddy TLS config)", iss))
		}
	}
	modes = uniqStrings(modes)
	summary = strings.Join(parts, " · ")
	if summary == "" {
		summary = "See issuer modules below."
	}
	return summary, modes, issuerNames, onDemand
}

func describeACMEIssuerChallenges(iss *caddytls.ACMEIssuer, globalDNS bool) (string, []string) {
	if iss == nil {
		return "", nil
	}
	var modes []string
	var parts []string
	if iss.Challenges == nil {
		modes = append(modes, "HTTP-01 (default)", "TLS-ALPN-01 (default)")
		if globalDNS {
			modes = append(modes, "DNS-01 (global TLS DNS provider)")
		}
		parts = append(parts, "ACME")
		return strings.Join(parts, " "), modes
	}
	ch := iss.Challenges
	if ch.HTTP == nil || !ch.HTTP.Disabled {
		modes = append(modes, "HTTP-01")
	}
	if ch.TLSALPN == nil || !ch.TLSALPN.Disabled {
		modes = append(modes, "TLS-ALPN-01")
	}
	if ch.DNS != nil && (len(ch.DNS.ProviderRaw) > 0 || globalDNS) {
		modes = append(modes, "DNS-01")
		parts = append(parts, "ACME with DNS challenge")
	} else {
		parts = append(parts, "ACME")
	}
	if len(modes) == 0 {
		modes = append(modes, "(all standard ACME challenges disabled in config)")
	}
	return strings.Join(parts, " "), modes
}

func uniqStrings(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func pickPrimaryCert(certs []certmagic.Certificate) certmagic.Certificate {
	if len(certs) == 0 {
		return certmagic.Certificate{}
	}
	best := certs[0]
	bestExp := certNotAfter(best)
	for i := 1; i < len(certs); i++ {
		t := certNotAfter(certs[i])
		if t.After(bestExp) {
			best = certs[i]
			bestExp = t
		}
	}
	return best
}

func certNotAfter(c certmagic.Certificate) time.Time {
	if c.Leaf != nil {
		return c.Leaf.NotAfter
	}
	return time.Time{}
}

func certIssuerString(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	if leaf.Issuer.String() != "" {
		return leaf.Issuer.String()
	}
	return leaf.Issuer.CommonName
}
