package main

import (
	"fmt"
	"os"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/vpnless/vpnless"
	_ "github.com/lucaslorentz/caddy-docker-proxy/v2"
)

func main() {
	// Default to docker-proxy when no command is provided.
	if len(os.Args) == 1 {
		os.Args = []string{
			os.Args[0],
			"docker-proxy",
			"--ingress-networks", "vpnless",
			"--caddyfile-path", "Caddyfile",
		}
	}
	if err := ensureDockerProxyPreflight(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	caddycmd.Main()
}
