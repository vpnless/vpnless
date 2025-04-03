package vpnless

import (
	"net/http/httptest"
	"testing"
)

func TestCookieDomainForRequest(t *testing.T) {
	tests := []struct {
		name         string
		override     string
		url          string
		expected     string
		overrideOnly bool
	}{
		{name: "explicit override wins", override: "vpnless.org", url: "https://foo.t.vpnless.org/", expected: "vpnless.org"},
		{name: "strip dotted override", override: ".vpnless.org", url: "https://foo.t.vpnless.org/", expected: "vpnless.org"},
		{name: "subdomain inferred parent", url: "https://foo.t.vpnless.org/", expected: "t.vpnless.org"},
		{name: "apex domain stays apex", url: "https://vpnless.org/", expected: "vpnless.org"},
		{name: "localhost host-only", url: "http://localhost:8080/", expected: ""},
		{name: "ipv4 host-only", url: "http://127.0.0.1:8080/", expected: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &DeviceAuth{CookieDomain: tc.override}
			req := httptest.NewRequest("GET", tc.url, nil)
			if got := m.cookieDomainForRequest(req); got != tc.expected {
				t.Fatalf("cookie domain mismatch: got %q, want %q", got, tc.expected)
			}
		})
	}
}
