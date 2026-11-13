//go:build darwin

package firewall

import (
	"context"
	"net/netip"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

type pfBackend struct {
	exec  posture.Exec
	pfctl string
}

// NewBackend returns the pf backend (anchor com.apple/250.DranzoRMM, which the
// stock /etc/pf.conf evaluates through its "com.apple/*" anchor).
func NewBackend(p platform.Platform) Backend {
	return pfBackend{exec: posture.Exec{Platform: p}, pfctl: posture.LookTool("pfctl")}
}

func (b pfBackend) Owned(ctx context.Context) ([]string, error) {
	if b.pfctl == "" {
		return nil, ErrUnsupported
	}
	res, err := b.exec.Run(ctx, posture.Cmd{Path: b.pfctl, Args: []string{"-a", PfAnchor, "-sr"}})
	if err != nil {
		return nil, err
	}
	return ParseOwnedIDs(res.Stdout), nil
}

func (b pfBackend) Apply(ctx context.Context, rules []Rule) error {
	if b.pfctl == "" {
		return ErrUnsupported
	}
	if len(rules) == 0 {
		_, err := b.exec.Run(ctx, posture.Cmd{Path: b.pfctl, Args: []string{"-a", PfAnchor, "-F", "rules"}})
		return err
	}
	if _, err := b.exec.Output(ctx, posture.Cmd{Path: b.pfctl, Args: []string{"-a", PfAnchor, "-f", "-"}, Stdin: RenderPf(rules)}); err != nil {
		return err
	}
	// pf is off by default on macOS; switch it on only when it is off.
	info, err := b.exec.Run(ctx, posture.Cmd{Path: b.pfctl, Args: []string{"-s", "info"}})
	if err == nil && !strings.Contains(info.Stdout, "Status: Enabled") {
		_, err = b.exec.Output(ctx, posture.Cmd{Path: b.pfctl, Args: []string{"-e"}})
		if err != nil && !strings.Contains(err.Error(), "already enabled") {
			return err
		}
	}
	return nil
}

// SupportsPrograms reports whether rules may name a program (Windows Firewall only).
const SupportsPrograms = false

type pfIsolation struct{ b pfBackend }

// NewIsolationBackend returns the pf isolation (anchor com.apple/200.DranzoRMMIsolation).
func NewIsolationBackend(p platform.Platform) IsolationBackend {
	return pfIsolation{b: pfBackend{exec: posture.Exec{Platform: p}, pfctl: posture.LookTool("pfctl")}}
}

func (i pfIsolation) Isolate(ctx context.Context, allow []netip.Addr) error {
	if i.b.pfctl == "" {
		return ErrUnsupported
	}
	if _, err := i.b.exec.Output(ctx, posture.Cmd{Path: i.b.pfctl, Args: []string{"-a", PfIsolationAnchor, "-f", "-"}, Stdin: RenderIsolationPf(allow)}); err != nil {
		return err
	}
	info, err := i.b.exec.Run(ctx, posture.Cmd{Path: i.b.pfctl, Args: []string{"-s", "info"}})
	if err == nil && !strings.Contains(info.Stdout, "Status: Enabled") {
		if _, err := i.b.exec.Output(ctx, posture.Cmd{Path: i.b.pfctl, Args: []string{"-e"}}); err != nil && !strings.Contains(err.Error(), "already enabled") {
			return err
		}
	}
	// Existing connections keep their pf state; drop them so only allowed traffic continues.
	_, _ = i.b.exec.Run(ctx, posture.Cmd{Path: i.b.pfctl, Args: []string{"-F", "states"}})
	return nil
}

func (i pfIsolation) Release(ctx context.Context) error {
	if i.b.pfctl == "" {
		return ErrUnsupported
	}
	_, err := i.b.exec.Run(ctx, posture.Cmd{Path: i.b.pfctl, Args: []string{"-a", PfIsolationAnchor, "-F", "rules"}})
	return err
}
