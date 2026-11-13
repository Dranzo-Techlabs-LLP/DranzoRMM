//go:build windows

package firewall

import (
	"context"
	"net/netip"
	"strings"

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

type winIsolation struct{ exec posture.Exec }

// NewIsolationBackend returns the Windows Firewall isolation (group "DranzoRMM Isolation").
func NewIsolationBackend(p platform.Platform) IsolationBackend {
	return winIsolation{exec: posture.Exec{Platform: p}}
}

func (w winIsolation) Isolate(ctx context.Context, allow []netip.Addr) error {
	// DNS servers, default gateway (often the DHCP server) and DHCP broadcast stay reachable.
	keep := append([]netip.Addr{}, allow...)
	if out, err := w.exec.Output(ctx, posture.PowerShell(PSIsolationKeep)); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if a, err := netip.ParseAddr(strings.TrimSpace(line)); err == nil && !a.IsUnspecified() {
				keep = append(keep, a)
			}
		}
	}
	v4 := strings.Join(ComplementRanges(keep, false), ",")
	v6 := strings.Join(ComplementRanges(keep, true), ",")
	_, err := w.exec.Output(ctx, posture.PowerShell(PSIsolate, "DRANZO_ISO_V4="+v4, "DRANZO_ISO_V6="+v6))
	return err
}

func (w winIsolation) Release(ctx context.Context) error {
	_, err := w.exec.Output(ctx, posture.PowerShell(PSReleaseIsolation))
	return err
}
