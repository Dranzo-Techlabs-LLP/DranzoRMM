//go:build windows

package firewall

import (
	"context"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

type winBackend struct{ exec posture.Exec }

// NewBackend returns the Windows Firewall backend.
func NewBackend(p platform.Platform) Backend { return winBackend{exec: posture.Exec{Platform: p}} }

func (b winBackend) Owned(ctx context.Context) ([]string, error) {
	out, err := b.exec.Output(ctx, posture.PowerShell(PSListRules))
	if err != nil {
		return nil, err
	}
	return ParseOwnedIDs(out), nil
}

func (b winBackend) Apply(ctx context.Context, rules []Rule) error {
	payload, err := WindowsPayload(rules)
	if err != nil {
		return err
	}
	_, err = b.exec.Output(ctx, posture.PowerShell(PSApplyRules, "DRANZO_FW_RULES="+payload))
	return err
}

// SupportsPrograms reports whether rules may name a program (Windows Firewall only).
const SupportsPrograms = true
