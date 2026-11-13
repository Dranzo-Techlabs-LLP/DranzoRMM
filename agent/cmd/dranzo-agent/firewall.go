package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/firewall"
	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// firewallManager is the manager of the rules DranzoRMM owns in the host firewall.
func firewallManager(p platform.Platform, paths config.Paths, serverURL func() string) *firewall.Manager {
	return &firewall.Manager{
		Backend:   firewall.NewBackend(p),
		StatePath: filepath.Join(paths.StateDir, "firewall-rules.json"),
		Reachable: func(ctx context.Context) error { return serverReachable(ctx, serverURL()) },
	}
}

// serverReachable opens (and closes) a TCP connection to the server's agent
// endpoint, retrying until ctx ends. It proves new connections still get through.
func serverReachable(ctx context.Context, serverURL string) error {
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("no server address: %q", serverURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	var last error
	for {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("cannot connect to %s", addr), last)
		case <-time.After(2 * time.Second):
		}
	}
}

// removeFirewallRules deletes every rule DranzoRMM created (uninstall). Best
// effort: an uninstall must not fail because the firewall tool is missing.
func removeFirewallRules(paths config.Paths) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	m := firewallManager(platform.New(), paths, func() string { return "" })
	m.Reachable = nil
	_ = m.Clear(ctx)
}
