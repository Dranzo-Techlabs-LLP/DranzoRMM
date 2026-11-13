//go:build darwin

package firewall

import (
	"context"
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
