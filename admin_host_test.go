package vpnless

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeAdminHostInput(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"off", ""},
		{"FALSE", ""},
		{"-", ""},
		{"vpnless.site", "vpnless.site"},
		{"VPNLESS.SITE", "vpnless.site"},
		{"https://vpnless.site", "vpnless.site"},
		{"http://vpnless.site:443", "vpnless.site"},
		{"https://vpnless.site/extra", "vpnless.site"},
	}
	for _, tc := range tests {
		if got := normalizeAdminHostInput(tc.in); got != tc.want {
			t.Fatalf("normalizeAdminHostInput(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestPairingRedirectTargetUsesAdminHost(t *testing.T) {
	m := &DeviceAuth{
		AdminHost:   "vpnless.site",
		PairingPath: "/vpnless/pair",
	}
	r := httptest.NewRequest("GET", "http://jellyfin.example.com/foo", nil)
	if got, want := m.pairingRedirectTarget(r), "http://vpnless.site/vpnless/pair"; got != want {
		t.Fatalf("pairingRedirectTarget = %q want %q", got, want)
	}
	m2 := &DeviceAuth{
		AdminHost:   "vpnless.site",
		PairingPath: "/vpnless/pair",
	}
	rSame := httptest.NewRequest("GET", "http://vpnless.site/x", nil)
	if got, want := m2.pairingRedirectTarget(rSame), "/vpnless/pair"; got != want {
		t.Fatalf("same-host pairingRedirectTarget = %q want %q", got, want)
	}
}

func TestPairingRedirectTargetHTTPSForwarded(t *testing.T) {
	m := &DeviceAuth{
		AdminHost:   "vpnless.site",
		PairingPath: "/vpnless/pair",
	}
	r := httptest.NewRequest("GET", "http://jellyfin.example.com/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got, want := m.pairingRedirectTarget(r), "https://vpnless.site/vpnless/pair"; got != want {
		t.Fatalf("pairingRedirectTarget = %q want %q", got, want)
	}
}

func TestAbsoluteURLOnAdminHostUsesTLS(t *testing.T) {
	m := &DeviceAuth{AdminHost: "vpnless.site"}
	r := httptest.NewRequest("GET", "https://x.example/vpnless/admin", nil)
	r.TLS = &tls.ConnectionState{}
	if got, want := m.absoluteURLOnAdminHost(r, "/vpnless/admin?a=1"), "https://vpnless.site/vpnless/admin?a=1"; got != want {
		t.Fatalf("absoluteURLOnAdminHost = %q want %q", got, want)
	}
}

func TestRedirectAdminHostRootToApproval(t *testing.T) {
	m := &DeviceAuth{
		AdminHost:    "less.vpnless.org",
		ApprovalPath: "/vpnless/admin",
	}
	r := httptest.NewRequest("GET", "https://less.vpnless.org/", nil)
	r.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	if !m.redirectAdminHostRootToApproval(rr, r) {
		t.Fatal("expected redirect")
	}
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("code=%d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/vpnless/admin" {
		t.Fatalf("Location=%q", loc)
	}
}

func TestRedirectAdminHostRootSkippedWithoutAdminHost(t *testing.T) {
	m := &DeviceAuth{ApprovalPath: "/vpnless/admin"}
	r := httptest.NewRequest("GET", "https://less.vpnless.org/", nil)
	rr := httptest.NewRecorder()
	if m.redirectAdminHostRootToApproval(rr, r) {
		t.Fatal("unexpected redirect")
	}
}

func TestRedirectAdminHostRootSkippedOnOtherVhost(t *testing.T) {
	m := &DeviceAuth{
		AdminHost:    "less.vpnless.org",
		ApprovalPath: "/vpnless/admin",
	}
	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	rr := httptest.NewRecorder()
	if m.redirectAdminHostRootToApproval(rr, r) {
		t.Fatal("unexpected redirect")
	}
}
