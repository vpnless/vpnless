package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

// ensureDockerProxyPreflight bails early if Docker is down or networks look wrong (docker-proxy entrypoint).
func ensureDockerProxyPreflight(args []string) error {
	if len(args) < 2 || args[1] != "docker-proxy" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	socketList := resolvedDockerSockets(args)
	clients, hostHints, err := dockerClientsForSockets(socketList)
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	for i, cli := range clients {
		ping, err := cli.Ping(ctx)
		if err != nil {
			hint := ""
			if i < len(hostHints) && hostHints[i] != "" {
				hint = fmt.Sprintf(" (host: %s)", hostHints[i])
			}
			return dockerPingError(hint, err)
		}
		_ = ping
	}

	ingress := strings.TrimSpace(os.Getenv("CADDY_INGRESS_NETWORKS"))
	if ingress == "" {
		ingress = parseLongFlag(args, "ingress-networks")
	}
	networks := splitCommaNonEmpty(ingress)
	if len(networks) == 0 {
		return nil
	}

	// Ingress networks are scoped to each daemon, so verify per host.
	for i, cli := range clients {
		sockHint := ""
		if i < len(hostHints) && hostHints[i] != "" {
			sockHint = fmt.Sprintf(" [Docker host: %s]", hostHints[i])
		}
		for _, netName := range networks {
			_, err := cli.NetworkInspect(ctx, netName, network.InspectOptions{})
			if err != nil {
				return fmt.Errorf("vpnless-caddy docker-proxy preflight:%s Docker network %q does not exist: %w\n"+
					"Create it (example): docker network create %s", sockHint, netName, err, netName)
			}
		}
	}
	return nil
}

func dockerPingError(hostHint string, err error) error {
	var msg strings.Builder
	msg.WriteString("vpnless-caddy docker-proxy preflight: cannot reach Docker daemon")
	if hostHint != "" {
		msg.WriteString(hostHint)
	}
	msg.WriteString(": ")
	msg.WriteString(err.Error())
	msg.WriteString("\nHints: start Docker (e.g. systemctl start docker on Linux); ensure your user can access the socket (group docker, or set DOCKER_HOST); ")
	msg.WriteString("for a remote daemon export DOCKER_HOST=tcp://... or pass --docker-sockets.")
	if errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		msg.WriteString(" Permission denied often means adding your user to the `docker` group (then re-login) or using sudo.")
	}
	return errors.New(msg.String())
}

func resolvedDockerSockets(args []string) []string {
	if env := strings.TrimSpace(os.Getenv("CADDY_DOCKER_SOCKETS")); env != "" {
		return splitCommaNonEmpty(env)
	}
	if f := parseLongFlag(args, "docker-sockets"); f != "" {
		return splitCommaNonEmpty(f)
	}
	return nil
}

func dockerClientsForSockets(socketPaths []string) ([]*client.Client, []string, error) {
	if len(socketPaths) == 0 {
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return nil, nil, fmt.Errorf("vpnless-caddy docker-proxy preflight: Docker client: %w", err)
		}
		host := cli.DaemonHost()
		return []*client.Client{cli}, []string{host}, nil
	}

	clients := make([]*client.Client, 0, len(socketPaths))
	hosts := make([]string, 0, len(socketPaths))
	for _, raw := range socketPaths {
		host := normalizeDockerHost(raw)
		cli, err := client.NewClientWithOpts(
			client.WithHost(host),
			client.WithAPIVersionNegotiation(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("vpnless-caddy docker-proxy preflight: Docker client for %q: %w", host, err)
		}
		clients = append(clients, cli)
		hosts = append(hosts, host)
	}
	return clients, hosts, nil
}

func normalizeDockerHost(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.Contains(s, "://") {
		return s
	}
	return "unix://" + s
}

func parseLongFlag(args []string, name string) string {
	key := "--" + name
	prefix := key + "="
	for i := 2; i < len(args); i++ {
		a := args[i]
		if a == key && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	return ""
}

func splitCommaNonEmpty(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
