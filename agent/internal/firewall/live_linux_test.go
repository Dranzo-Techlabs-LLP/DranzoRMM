//go:build linux

package firewall

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// TestLiveNftables applies, lists and removes real nftables rules. Opt-in:
// DRANZO_LIVE_FIREWALL=1, as root with nft installed (a throwaway container).
func TestLiveNftables(t *testing.T) {
	if os.Getenv("DRANZO_LIVE_FIREWALL") != "1" {
		t.Skip("set DRANZO_LIVE_FIREWALL=1 in a throwaway container")
	}
	ctx := context.Background()
	b := NewBackend(platform.New())
	rules := mustRules(t, nftRules)
	if err := b.Apply(ctx, rules); err != nil {
		t.Fatal(err)
	}
	owned, err := b.Owned(ctx)
	if err != nil {
		t.Fatal(err)
	}
	missing, unexpected := Diff(owned, rules)
	if len(missing) != 0 || len(unexpected) != 0 {
		t.Fatalf("after apply: owned %v missing %v unexpected %v", owned, missing, unexpected)
	}
	// Replacing is atomic and idempotent.
	if err := b.Apply(ctx, rules[:1]); err != nil {
		t.Fatal(err)
	}
	if owned, _ = b.Owned(ctx); len(owned) != 1 {
		t.Fatalf("after replace: %v", owned)
	}
	if err := b.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if owned, _ = b.Owned(ctx); len(owned) != 0 {
		t.Fatalf("after clear: %v", owned)
	}
}

// TestLiveIsolation isolates a throwaway container: an outside host becomes
// unreachable, the allowed host and loopback stay reachable, release restores.
func TestLiveIsolation(t *testing.T) {
	if os.Getenv("DRANZO_LIVE_FIREWALL") != "1" {
		t.Skip("set DRANZO_LIVE_FIREWALL=1 in a throwaway container")
	}
	ctx := context.Background()
	dial := func(addr string) error {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	const allowed, other = "1.1.1.1:443", "1.0.0.1:443"
	if dial(allowed) != nil || dial(other) != nil {
		t.Skip("no internet in this container")
	}
	b := NewIsolationBackend(platform.New())
	if err := b.Isolate(ctx, []netip.Addr{netip.MustParseAddr("1.1.1.1")}); err != nil {
		t.Fatal(err)
	}
	if err := dial(allowed); err != nil {
		t.Errorf("allowed host unreachable while isolated: %v", err)
	}
	if err := dial(other); err == nil {
		t.Error("other host still reachable while isolated")
	}
	if err := b.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dial(other); err != nil {
		t.Errorf("other host unreachable after release: %v", err)
	}
}
