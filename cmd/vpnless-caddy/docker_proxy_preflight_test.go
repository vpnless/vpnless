package main

import (
	"reflect"
	"testing"
)

func TestParseLongFlag(t *testing.T) {
	args := []string{"vpnless-caddy", "docker-proxy", "--foo", "bar", "--ingress-networks", "a,b", "--caddyfile-path", "Caddyfile"}
	if g := parseLongFlag(args, "ingress-networks"); g != "a,b" {
		t.Fatalf("ingress-networks: got %q", g)
	}
	if g := parseLongFlag([]string{"x", "docker-proxy", "--ingress-networks=onlyone"}, "ingress-networks"); g != "onlyone" {
		t.Fatalf("ingress-networks=: got %q", g)
	}
	if g := parseLongFlag([]string{"x", "run"}, "ingress-networks"); g != "" {
		t.Fatalf("missing: got %q", g)
	}
}

func TestSplitCommaNonEmpty(t *testing.T) {
	got := splitCommaNonEmpty(" vpnless , foo , ")
	want := []string{"vpnless", "foo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if g := splitCommaNonEmpty(""); len(g) != 0 {
		t.Fatalf("empty: %#v", g)
	}
}
