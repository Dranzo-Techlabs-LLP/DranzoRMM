package main

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/firewall"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

func init() { features = append(features, wireIsolation) }

const (
	isolationTitle   = "Network access restricted"
	isolationDefault = "Your IT team has isolated this computer from the network for security reasons. Only the IT management service can reach it. Contact your IT team for help."
	releaseTitle     = "Network access restored"
	releaseDefault   = "Your IT team has restored this computer's network access."
	maxMessage       = 512
	maxAllow         = 8
)

func isolator(p platform.Platform, paths config.Paths, serverURL func() string) *firewall.Isolator {
	return &firewall.Isolator{
		Backend:   firewall.NewIsolationBackend(p),
		StatePath: filepath.Join(paths.StateDir, "isolation.json"),
		Reachable: func(ctx context.Context) error { return serverReachable(ctx, serverURL()) },
	}
}

// userMessage keeps a server-provided message printable and bounded.
func userMessage(m, fallback string) string {
	m = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, m))
	if m == "" {
		return fallback
	}
	if len(m) > maxMessage {
		m = m[:maxMessage]
	}
	return m
}

// wireIsolation registers network.isolate and network.release, and re-applies
// a saved isolation at start (nftables and pf rules do not survive a reboot).
func wireIsolation(a *agentcore.Agent) error {
	env := a.Env()
	iso := isolator(env.Platform, env.Paths, func() string { return a.Config().ServerURL })
	ui := userui.New(env.Platform)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if restored, err := iso.Restore(ctx); err != nil {
		env.Log.Error("isolation: re-applying the saved isolation failed", slog.String("error", err.Error()))
	} else if restored {
		env.Log.Warn("isolation: this device is isolated; re-applied at start")
	}
	cancel()

	a.Jobs().Register(protocol.KindNetworkIsolate, jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
		var spec protocol.NetworkIsolateSpec
		if err := jc.DecodeSpec(&spec); err != nil {
			return jobs.Rejected("%v", err)
		}
		if len(spec.Allow) > maxAllow {
			return jobs.Rejected("at most %d extra endpoints", maxAllow)
		}
		extra := make([]firewall.Endpoint, 0, len(spec.Allow))
		for _, e := range spec.Allow {
			ep := firewall.Endpoint{Host: e.Host, Port: e.Port}
			if !firewall.ValidEndpoint(ep) {
				return jobs.Rejected("invalid endpoint %q", e.Host)
			}
			extra = append(extra, ep)
		}
		allowed, err := iso.Isolate(jc.Ctx, a.Config().ServerURL, extra)
		if err != nil {
			return jobs.Failed("isolation: %v", err)
		}
		jc.Log.Warn("device isolated", slog.Any("allowed", addrStrings(allowed)))
		_ = ui.Notify(jc.Ctx, isolationTitle, userMessage(spec.Message, isolationDefault))
		return jobs.SucceededWith(protocol.NetworkIsolateResult{Allowed: addrStrings(allowed)})
	}))

	a.Jobs().Register(protocol.KindNetworkRelease, jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
		var spec protocol.NetworkReleaseSpec
		if err := jc.DecodeSpec(&spec); err != nil {
			return jobs.Rejected("%v", err)
		}
		if err := iso.Release(jc.Ctx); err != nil {
			return jobs.Failed("release isolation: %v", err)
		}
		jc.Log.Warn("device isolation released")
		_ = ui.Notify(jc.Ctx, releaseTitle, userMessage(spec.Message, releaseDefault))
		return jobs.Succeeded()
	}))
	return nil
}

func addrStrings(in []netip.Addr) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.String())
	}
	return out
}

// releaseIsolationLocal removes an isolation without the server (local
// administrator, or uninstall).
func releaseIsolationLocal(paths config.Paths) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return isolator(platform.New(), paths, func() string { return "" }).Release(ctx)
}
