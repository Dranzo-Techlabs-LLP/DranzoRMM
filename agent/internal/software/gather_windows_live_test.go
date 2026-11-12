//go:build windows

package software

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Live Windows tests (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit). They only read the system; "winget list" may
// refresh winget's source index from Microsoft's servers.

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

func TestWindowsLiveRegistryViews(t *testing.T) {
	requireLiveWindows(t)
	native, err := readUninstallView(registry.WOW64_64KEY, "64")
	if err != nil {
		t.Fatalf("64-bit uninstall view: %v", err)
	}
	wow, err := readUninstallView(registry.WOW64_32KEY, "32")
	if err != nil {
		t.Fatalf("32-bit uninstall view: %v", err)
	}
	t.Logf("uninstall entries: 64-bit view %d, 32-bit view %d", len(native), len(wow))
	if len(native)+len(wow) == 0 {
		t.Fatal("no uninstall entries at all")
	}
	items := RegistryItems(append(native, wow...))
	if len(items) == 0 {
		t.Fatal("no registry items after filtering")
	}
}

func TestWindowsLiveSoftwareInventory(t *testing.T) {
	requireLiveWindows(t)
	winget := LookupTool("winget")
	t.Logf("winget: %q (PATH lookup and %%ProgramFiles%%\\WindowsApps)", winget)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	inv := NewCollector(platform.New()).Collect(ctx)
	t.Logf("collected in %v: %d items, truncated=%v, unsupported=%v", time.Since(start).Round(time.Millisecond), len(inv.Items), inv.Truncated, inv.Unsupported)

	count := map[string]int{}
	noVersion := 0
	for i, it := range inv.Items {
		count[it.Source]++
		if strings.TrimSpace(it.Name) == "" {
			t.Errorf("item without a name: %+v", it)
		}
		if it.Source != protocol.SourceRegistry && it.Source != protocol.SourceWinget {
			t.Errorf("unexpected source: %+v", it)
		}
		if it.Version == "" {
			noVersion++
		}
		if i < 15 {
			t.Logf("  %+v", it)
		}
	}
	t.Logf("by source: %v, items without a version: %d", count, noVersion)

	if count[protocol.SourceRegistry] == 0 {
		t.Fatal("the registry scan returned no programs")
	}
	if noVersion*2 > len(inv.Items) {
		t.Errorf("more than half of the items have no version (%d of %d)", noVersion, len(inv.Items))
	}
	for _, u := range inv.Unsupported {
		if u != protocol.SourceWinget {
			t.Errorf("unexpected unsupported source %q", u)
		}
	}

	// winget: either items with source winget, or "winget" in unsupported.
	wingetUnsupported := false
	for _, u := range inv.Unsupported {
		wingetUnsupported = wingetUnsupported || u == protocol.SourceWinget
	}
	switch {
	case count[protocol.SourceWinget] > 0 && !wingetUnsupported:
		t.Logf("RESULT winget: used (%d winget-only items)", count[protocol.SourceWinget])
	case count[protocol.SourceWinget] == 0 && wingetUnsupported:
		t.Logf("RESULT winget: unsupported in this context (winget path %q)", winget)
	case count[protocol.SourceWinget] == 0 && !wingetUnsupported:
		// winget ran and listed only programs the registry already knows.
		t.Logf("RESULT winget: used, no winget-only items")
	default:
		t.Errorf("winget items present and winget listed as unsupported")
	}

	// The raw winget call, for the record (the collector hides its failures).
	if winget != "" {
		res, err := Output(ctx, platform.New(), listTimeout, platform.Command{
			Path: winget, Args: []string{"list", "--accept-source-agreements", "--disable-interactivity"},
		})
		if err != nil {
			t.Logf("winget list: %v", err)
		} else {
			rows := ParseWingetTable(res.Stdout)
			head := res.Stdout
			if len(head) > 1500 {
				head = head[:1500]
			}
			t.Logf("winget list: exit %d, %d parsed rows, stderr %q\nstdout head:\n%s", res.ExitCode, len(rows), Clean(res.Stderr, 300), head)
		}
	}
}
