//go:build windows

package patch

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
)

// Live Windows tests (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit). The scan is read-only (IUpdateSearcher.Search).
// Installing is a second opt-in: DRANZO_REAL_WINDOWS_PATCH_INSTALL=1.

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

func logPending(t *testing.T, pending []protocol.PendingPatch) {
	t.Helper()
	for i, p := range pending {
		if i >= 25 {
			t.Logf("  ... %d more", len(pending)-i)
			break
		}
		size := int64(-1)
		if p.SizeBytes != nil {
			size = *p.SizeBytes
		}
		t.Logf("  %s | %s | kb=%s cat=%s sev=%s size=%d reboot=%v", p.ID, p.Title, p.KB, p.Category, p.Severity, size, p.RequiresReboot)
	}
}

// TestWindowsLiveWUAScan runs the embedded WUA scan script through the real
// provider. Windows Update can take several minutes to answer.
func TestWindowsLiveWUAScan(t *testing.T) {
	requireLiveWindows(t)
	plat := platform.New()
	p := &WUAProvider{Plat: plat, Lookup: software.LookupTool}
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("WUA provider check: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	start := time.Now()
	res, err := p.Scan(ctx, false)
	t.Logf("WUA scan took %v: %d pending, rebootRequired=%v lastInstallAt=%v err=%v",
		time.Since(start).Round(time.Second), len(res.Pending), res.RebootRequired, res.LastInstallAt, err)
	if err != nil {
		// Show what the script printed, for the record.
		out, oerr := software.Output(ctx, plat, scanTimeout, p.command(wuaScanScript, nil))
		t.Logf("raw run: exit=%d err=%v\nstdout=%q\nstderr=%q", out.ExitCode, oerr, software.Clean(out.Stdout, 2000), software.Clean(out.Stderr, 2000))
		t.Fatalf("WUA scan failed: %v", err)
	}
	logPending(t, res.Pending)
	for _, u := range res.Pending {
		if u.Source != SourceWUA || !protocol.ValidPackageID(u.ID) || u.Title == "" || u.Category == "" || u.Severity == "" {
			t.Errorf("pending update not well formed: %+v", u)
		}
		if _, native, ok := DecodeID(u.ID); !ok || !ValidGUID(native) {
			t.Errorf("update id %q does not decode to a GUID", u.ID)
		}
	}
	if res.LastInstallAt != nil && res.LastInstallAt.After(time.Now().Add(48*time.Hour)) {
		t.Errorf("last install in the future: %v", res.LastInstallAt)
	}
}

// TestWindowsLivePatchState runs the whole patch.state collection (WUA and
// winget) the way the agent reports it.
func TestWindowsLivePatchState(t *testing.T) {
	requireLiveWindows(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	start := time.Now()
	st := NewScanner(platform.New()).Collect(ctx)
	t.Logf("patch.state in %v: pending=%d rebootRequired=%v lastInstallAt=%v unsupported=%v scanError=%q",
		time.Since(start).Round(time.Second), len(st.Pending), st.RebootRequired, st.LastInstallAt, st.Unsupported, st.ScanError)
	logPending(t, st.Pending)
	for _, u := range st.Unsupported {
		if u != SourceWinget {
			t.Errorf("unexpected unsupported source %q", u)
		}
	}
	if strings.Contains(st.ScanError, SourceWUA+":") {
		t.Errorf("WUA scan error: %s", st.ScanError)
	} else if st.ScanError != "" {
		t.Logf("RESULT non-WUA scan problem (winget): %s", st.ScanError)
	}
}

// pickUpdates chooses what the opt-in install test installs: the ids in
// DRANZO_REAL_WINDOWS_PATCH_IDS, else a Defender definition update (small, no
// restart), else the smallest pending update that is neither a driver nor a
// feature upgrade.
func pickUpdates(t *testing.T, pending []protocol.PendingPatch) []string {
	t.Helper()
	if ids := strings.TrimSpace(os.Getenv("DRANZO_REAL_WINDOWS_PATCH_IDS")); ids != "" {
		return strings.Split(ids, ",")
	}
	var wua []protocol.PendingPatch
	for _, p := range pending {
		if p.Source == SourceWUA {
			wua = append(wua, p)
		}
	}
	for _, p := range wua {
		if p.Category == CategoryDefinition {
			return []string{p.ID}
		}
	}
	sort.SliceStable(wua, func(i, j int) bool {
		si, sj := int64(1<<62), int64(1<<62)
		if wua[i].SizeBytes != nil {
			si = *wua[i].SizeBytes
		}
		if wua[j].SizeBytes != nil {
			sj = *wua[j].SizeBytes
		}
		return si < sj
	})
	for _, p := range wua {
		if p.Category != CategoryDriver && p.Category != CategoryFeature {
			return []string{p.ID}
		}
	}
	return nil
}

// TestWindowsLivePatchInstall installs ONE pending Windows update through the
// patch.install handler (reboot mode "never": the agent itself does not
// restart the machine, but the update may need a restart to finish).
func TestWindowsLivePatchInstall(t *testing.T) {
	requireLiveWindows(t)
	if os.Getenv("DRANZO_REAL_WINDOWS_PATCH_INSTALL") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS_PATCH_INSTALL=1 to install a Windows update for real")
	}
	plat := platform.New()
	scanner := NewScanner(plat)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()
	before := scanner.Collect(ctx)
	if strings.Contains(before.ScanError, SourceWUA+":") {
		t.Fatalf("scan before install failed: %s", before.ScanError)
	}
	ids := pickUpdates(t, before.Pending)
	if len(ids) == 0 {
		t.Skip("no pending Windows update to install")
	}
	t.Logf("installing %v", ids)
	h := NewInstallHandler(scanner, nil, nil)
	job := swtest.NewJob(ctx, plat, t.TempDir(), protocol.PatchInstallSpec{
		UpdateIDs: ids,
		Reboot:    protocol.RebootPolicy{Mode: RebootNever},
	})
	start := time.Now()
	res := h.Handle(job.JobContext)
	out := job.Out.String() + "\n" + job.ErrOut.String()
	if len(out) > 4000 {
		out = "..." + out[len(out)-4000:]
	}
	t.Logf("patch.install after %v: status=%s message=%q result=%+v\n%s", time.Since(start).Round(time.Second), res.Status, res.Message, res.Result, out)
	r, ok := res.Result.(protocol.PatchInstallResult)
	if res.Status != protocol.StatusSucceeded || !ok {
		t.Fatalf("status %s (%s)", res.Status, res.Message)
	}
	for _, it := range r.Installed {
		if !it.OK {
			t.Errorf("not installed: %+v", it)
		}
	}
	after := scanner.Collect(ctx)
	for _, p := range after.Pending {
		for _, id := range ids {
			if p.ID == id && !r.RebootRequired {
				t.Errorf("%s still pending after installation", id)
			}
		}
	}
	t.Logf("after install: pending=%d rebootRequired=%v (a restart of the VM may be needed to finish)", len(after.Pending), after.RebootRequired || r.RebootRequired)
}
