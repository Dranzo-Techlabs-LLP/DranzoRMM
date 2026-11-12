//go:build linux

package patch

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
)

// TestRealPatchScan runs the real scanner (opt-in, used in the Debian and
// Rocky Linux test containers). DRANZO_EXPECT_PENDING=1 requires at least one
// pending update; DRANZO_REAL_PATCH_INSTALL=<source:name,...> then installs
// those updates through the patch.install handler (reboot mode never).
func TestRealPatchScan(t *testing.T) {
	if os.Getenv("DRANZO_REAL_LINUX") != "1" {
		t.Skip("set DRANZO_REAL_LINUX=1 to scan this system for updates")
	}
	plat := platform.New()
	scanner := NewScanner(plat)
	st := scanner.Collect(context.Background())
	sec := 0
	for _, p := range st.Pending {
		if p.Category == CategorySecurity {
			sec++
		}
		if !protocol.ValidPackageID(p.ID) || p.Title == "" || p.NewVersion == "" {
			t.Fatalf("bad entry %+v", p)
		}
	}
	t.Logf("pending=%d security=%d rebootRequired=%v lastInstallAt=%v unsupported=%v scanError=%q", len(st.Pending), sec, st.RebootRequired, st.LastInstallAt, st.Unsupported, st.ScanError)
	for i, p := range st.Pending {
		if i < 5 {
			t.Logf("  %+v", p)
		}
	}
	if st.ScanError != "" || len(st.Unsupported) != 0 {
		t.Fatalf("scan error %q, unsupported %v", st.ScanError, st.Unsupported)
	}
	if os.Getenv("DRANZO_EXPECT_PENDING") == "1" && len(st.Pending) == 0 {
		t.Fatal("expected pending updates")
	}
	ids := os.Getenv("DRANZO_REAL_PATCH_INSTALL")
	if ids == "" {
		return
	}
	h := NewInstallHandler(scanner, nil, nil)
	job := swtest.NewJob(context.Background(), plat, t.TempDir(), protocol.PatchInstallSpec{
		UpdateIDs: strings.Split(ids, ","),
		Reboot:    protocol.RebootPolicy{Mode: RebootNever},
	})
	res := h.Handle(job.JobContext)
	out := job.Out.String()
	if len(out) > 2000 {
		out = "..." + out[len(out)-2000:]
	}
	t.Logf("patch.install status=%s message=%q result=%+v\n%s", res.Status, res.Message, res.Result, out)
	r, ok := res.Result.(protocol.PatchInstallResult)
	if res.Status != protocol.StatusSucceeded || !ok {
		t.Fatalf("status %s (%s) stderr %s", res.Status, res.Message, job.ErrOut.String())
	}
	for _, it := range r.Installed {
		if !it.OK {
			t.Fatalf("not installed: %+v", it)
		}
	}
	after := scanner.Collect(context.Background())
	for _, p := range after.Pending {
		for _, id := range strings.Split(ids, ",") {
			if p.ID == id {
				t.Fatalf("%s still pending after installation", id)
			}
		}
	}
	t.Logf("after install: pending=%d", len(after.Pending))
}
