//go:build linux

package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

type nftBackend struct {
	exec posture.Exec
	nft  string
}

// NewBackend returns the nftables backend (table inet dranzormm).
func NewBackend(p platform.Platform) Backend {
	return nftBackend{exec: posture.Exec{Platform: p}, nft: posture.LookTool("nft")}
}

func (b nftBackend) Owned(ctx context.Context) ([]string, error) {
	if b.nft == "" {
		return nil, ErrUnsupported
	}
	res, err := b.exec.Run(ctx, posture.Cmd{Path: b.nft, Args: []string{"-j", "list", "table", "inet", NftTable}, Env: []string{"LC_ALL=C"}})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if strings.Contains(res.Stderr, "No such file") || strings.Contains(res.Stderr, "does not exist") {
			return nil, nil // table not created yet
		}
		return nil, errors.New(posture.OneLine(res.Combined(), 300))
	}
	return ParseOwnedIDs(res.Stdout), nil
}

func (b nftBackend) Apply(ctx context.Context, rules []Rule) error {
	if b.nft == "" {
		return ErrUnsupported
	}
	script := RenderNft(rules)
	if len(rules) == 0 {
		script = "add table inet " + NftTable + "\ndelete table inet " + NftTable + "\n"
	}
	_, err := b.exec.Output(ctx, posture.Cmd{Path: b.nft, Args: []string{"-f", "-"}, Stdin: script, Env: []string{"LC_ALL=C"}})
	return err
}

// SupportsPrograms reports whether rules may name a program (Windows Firewall only).
const SupportsPrograms = false

type nftIsolation struct{ b nftBackend }

// NewIsolationBackend returns the nftables isolation (table inet dranzormm_isolation).
func NewIsolationBackend(p platform.Platform) IsolationBackend {
	return nftIsolation{b: nftBackend{exec: posture.Exec{Platform: p}, nft: posture.LookTool("nft")}}
}

func (n nftIsolation) Isolate(ctx context.Context, allow []netip.Addr) error {
	if n.b.nft == "" {
		return ErrUnsupported
	}
	_, err := n.b.exec.Output(ctx, posture.Cmd{Path: n.b.nft, Args: []string{"-f", "-"}, Stdin: RenderIsolationNft(allow), Env: []string{"LC_ALL=C"}})
	return err
}

func (n nftIsolation) Release(ctx context.Context) error {
	if n.b.nft == "" {
		return ErrUnsupported
	}
	script := "add table inet " + NftIsolationTable + "\ndelete table inet " + NftIsolationTable + "\n"
	_, err := n.b.exec.Output(ctx, posture.Cmd{Path: n.b.nft, Args: []string{"-f", "-"}, Stdin: script, Env: []string{"LC_ALL=C"}})
	return err
}
