//go:build linux

package firewall

import (
	"context"
	"os"
	"testing"

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
