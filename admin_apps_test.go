package vpnless

import "testing"

func TestResolveHomarrIconURL(t *testing.T) {
	if got := resolveHomarrIconURL(""); got != "" {
		t.Fatalf("empty: got %q", got)
	}
	if got := resolveHomarrIconURL("https://example.com/x.png"); got != "https://example.com/x.png" {
		t.Fatalf("url: got %q", got)
	}
	if got := resolveHomarrIconURL("portainer"); got != homarrIconsPNGBase+"portainer.png" {
		t.Fatalf("short name: got %q", got)
	}
	if got := resolveHomarrIconURL("foo.svg"); got != homarrIconsSVGBase+"foo.svg" {
		t.Fatalf("svg: got %q", got)
	}
}
