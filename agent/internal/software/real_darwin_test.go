//go:build darwin

package software_test

import (
	"context"
	"os"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// TestRealMacOSInventory runs the real collectors on this Mac. Opt-in
// (DRANZO_REAL_MACOS=1) so that CI does not depend on the machine's state.
// It needs no root: application bundles, pkgutil receipts and, when present,
// Homebrew (which runs as the current, unprivileged user).
func TestRealMacOSInventory(t *testing.T) {
	if os.Getenv("DRANZO_REAL_MACOS") != "1" {
		t.Skip("set DRANZO_REAL_MACOS=1 to run the collectors on this Mac")
	}
	inv := software.NewCollector(platform.New()).Collect(context.Background())
	count := map[string]int{}
	versioned := map[string]int{}
	var calculator *protocol.SoftwareItem
	for i, it := range inv.Items {
		count[it.Source]++
		if it.Version != "" {
			versioned[it.Source]++
		}
		if it.ID == "com.apple.calculator" {
			calculator = &inv.Items[i]
		}
		if it.Name == "" {
			t.Fatalf("item without a name: %+v", it)
		}
	}
	t.Logf("items: %d (%v), with version: %v, truncated=%v, unsupported=%v", len(inv.Items), count, versioned, inv.Truncated, inv.Unsupported)
	if count[protocol.SourceApp] < 20 || versioned[protocol.SourceApp] < count[protocol.SourceApp]*8/10 {
		t.Errorf("application bundles: %d found, %d with a version", count[protocol.SourceApp], versioned[protocol.SourceApp])
	}
	if calculator == nil || calculator.Name != "Calculator" || calculator.Version == "" {
		t.Errorf("Calculator.app not found with a version: %+v", calculator)
	}
	if count[protocol.SourcePkgutil] < 5 || versioned[protocol.SourcePkgutil] < count[protocol.SourcePkgutil]*8/10 {
		t.Errorf("pkgutil receipts: %d found, %d with a version", count[protocol.SourcePkgutil], versioned[protocol.SourcePkgutil])
	}
	if software.LookupTool("brew") != "" {
		if count[protocol.SourceBrew] == 0 {
			t.Errorf("Homebrew is installed but no formula or cask was reported")
		}
	} else if count[protocol.SourceBrew] != 0 {
		t.Errorf("brew items without brew")
	}
	if len(inv.Unsupported) != 0 {
		t.Errorf("unsupported = %v", inv.Unsupported)
	}
	for i := 1; i < len(inv.Items); i++ {
		if inv.Items[i-1] == inv.Items[i] {
			t.Errorf("duplicate item %+v", inv.Items[i])
		}
	}
}
