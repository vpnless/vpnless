package vpnless

import (
	"net/http/httptest"
	"testing"
)

func TestTortureChamberListOrdersByLatestPerIP(t *testing.T) {
	c := newTortureChamber(20)

	r1 := httptest.NewRequest("GET", "/a", nil)
	r1.RemoteAddr = "192.0.2.1:1234"
	s1 := c.begin("192.0.2.1", "tarpit", r1)
	c.appendOut(s1, "one")
	c.appendOut(s1, "two")
	c.end(s1)

	r2 := httptest.NewRequest("POST", "/b", nil)
	r2.RemoteAddr = "192.0.2.2:9999"
	s2 := c.begin("192.0.2.2", "honeypot", r2)
	c.appendOut(s2, "bee")
	c.end(s2)

	r3 := httptest.NewRequest("GET", "/c", nil)
	r3.RemoteAddr = "192.0.2.1:5555"
	s3 := c.begin("192.0.2.1", "slop", r3)
	c.appendOut(s3, "slime")
	c.end(s3)

	rows := c.listByIPLatest()
	if len(rows) != 2 {
		t.Fatalf("want 2 IPs, got %d", len(rows))
	}
	// 192.0.2.1 was tortured last → first row
	if rows[0].IP != "192.0.2.1" || rows[0].Mode != "slop" {
		t.Fatalf("want first row 192.0.2.1 slop, got %+v", rows[0])
	}
	if len(rows[0].PreviewOut) < 1 || rows[0].PreviewOut[len(rows[0].PreviewOut)-1] != "slime" {
		t.Fatalf("unexpected preview for first row: %#v", rows[0].PreviewOut)
	}
	if rows[1].IP != "192.0.2.2" {
		t.Fatalf("want second row 192.0.2.2, got %+v", rows[1])
	}
}
