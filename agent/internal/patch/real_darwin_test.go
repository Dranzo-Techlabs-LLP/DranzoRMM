//go:build darwin

package patch

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// TestRealMacOSPatchScan runs softwareupdate --list and (when installed)
// brew outdated on this Mac without root. Opt-in (DRANZO_REAL_MACOS=1); the
// index refresh (brew update) is skipped so the test changes nothing.
func TestRealMacOSPatchScan(t *testing.T) {
	if os.Getenv("DRANZO_REAL_MACOS") != "1" {
		t.Skip("set DRANZO_REAL_MACOS=1 to scan this Mac for updates")
	}
	s := NewScanner(platform.New())
	s.Refresh = false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st := s.Collect(ctx)
	count := map[string]int{}
	for _, p := range st.Pending {
		count[p.Source]++
		if !protocol.ValidPackageID(p.ID) || p.Title == "" {
			t.Fatalf("bad entry %+v", p)
		}
		if _, _, ok := DecodeID(p.ID); !ok {
			t.Fatalf("id does not decode: %s", p.ID)
		}
	}
	t.Logf("pending=%d %v rebootRequired=%v unsupported=%v scanError=%q", len(st.Pending), count, st.RebootRequired, st.Unsupported, st.ScanError)
	for i, p := range st.Pending {
		if i < 4 || p.Source == SourceSoftwareUpdate {
			t.Logf("  %+v", p)
		}
	}
	if st.ScanError != "" || len(st.Unsupported) != 0 {
		t.Fatalf("scanError %q unsupported %v", st.ScanError, st.Unsupported)
	}
}
