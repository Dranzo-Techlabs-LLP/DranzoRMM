package patch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/reboot"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

var alice = &platform.User{Name: "alice", UID: "501", GID: "20", Home: "/Users/alice"}

func wingetFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- scanner ----

func TestScannerApt(t *testing.T) {
	hist := filepath.Join(t.TempDir(), "history.log")
	if err := os.WriteFile(hist, []byte(fixture(t, "apt_history.log")), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		switch {
		case strings.HasSuffix(c.Line(), "apt-get -o DPkg::Lock::Timeout=60 update"):
			return swtest.Reply{}
		case strings.HasSuffix(c.Line(), "apt list --upgradable"):
			return swtest.Reply{Stdout: fixture(t, "apt_list_upgradable_debian12.txt"), Stderr: "WARNING: apt does not have a stable CLI interface.\n"}
		}
		return swtest.Reply{Exit: 1}
	}}
	plat := rec.Platform(nil)
	plat.Reboot = true
	s := NewScannerWith(plat,
		&AptProvider{Plat: plat, Lookup: swtest.Lookup("apt-get", "apt"), HistoryLog: hist},
		&DnfProvider{Plat: plat, Lookup: swtest.Lookup("apt-get", "apt")})
	st := s.Collect(context.Background())
	if len(st.Pending) != 2 || st.ScanError != "" || len(st.Unsupported) != 0 || !st.RebootRequired || st.LastInstallAt == nil {
		t.Fatalf("state = %+v", st)
	}
	p := st.Pending[0]
	if p.ID != "apt:libssl3" || p.Category != CategorySecurity || p.Source != SourceApt || p.CurrentVersion != "3.0.20-1~deb12u2" || p.NewVersion != "3.0.22-1~deb12u2" {
		t.Fatalf("pending[0] = %+v", p)
	}
	want := []string{"/fake/bin/apt-get -o DPkg::Lock::Timeout=60 update", "/fake/bin/apt list --upgradable"}
	if got := rec.Lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	for _, c := range rec.Calls() {
		if !c.HasEnv("DEBIAN_FRONTEND=noninteractive") || !c.HasEnv("LC_ALL=C") {
			t.Fatalf("env = %v", c.Env)
		}
	}

	// Without "apt": the simulation is parsed; a failing refresh is a warning only.
	rec = &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Line(), " update") {
			return swtest.Reply{Exit: 100}
		}
		return swtest.Reply{Stdout: fixture(t, "apt_simulate_debian12.txt")}
	}}
	plat = rec.Platform(nil)
	s = NewScannerWith(plat, &AptProvider{Plat: plat, Lookup: swtest.Lookup("apt-get")})
	st = s.Collect(context.Background())
	if len(st.Pending) != 2 || !strings.Contains(st.ScanError, "apt-get update exited with code 100") {
		t.Fatalf("simulate: %+v", st)
	}
	if got := rec.Lines()[1]; got != "/fake/bin/apt-get -s -o Debug::NoLocking=1 dist-upgrade" {
		t.Fatalf("simulate command = %s", got)
	}
}

func TestScannerDnf(t *testing.T) {
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		line := c.Line()
		switch {
		case strings.Contains(line, "check-update"):
			return swtest.Reply{Stdout: fixture(t, "dnf_check_update_rocky9.txt"), Exit: 100}
		case strings.Contains(line, "updateinfo"):
			return swtest.Reply{Stdout: fixture(t, "dnf_updateinfo_security_rocky9.txt")}
		case strings.Contains(line, "rpm -q --qf"):
			return swtest.Reply{Stdout: "bash.aarch64\t0\t5.1.8\t6.el9_1\ncurl-minimal.aarch64\t0\t7.76.1\t26.el9_3.2\n"}
		case strings.Contains(line, "rpm -qa"):
			return swtest.Reply{Stdout: "1700432736\n1731000000\n"}
		}
		return swtest.Reply{Exit: 1}
	}}
	plat := rec.Platform(nil)
	s := NewScannerWith(plat, &AptProvider{Plat: plat, Lookup: swtest.Lookup("dnf", "rpm")}, &DnfProvider{Plat: plat, Lookup: swtest.Lookup("dnf", "rpm")})
	st := s.Collect(context.Background())
	if len(st.Pending) != 112 || st.ScanError != "" || len(st.Unsupported) != 0 {
		t.Fatalf("pending %d, scanError %q, unsupported %v", len(st.Pending), st.ScanError, st.Unsupported)
	}
	bash := findPatch(st.Pending, "dnf:bash.aarch64")
	if bash == nil || bash.CurrentVersion != "5.1.8-6.el9_1" || bash.NewVersion != "5.1.8-9.el9" || bash.Category != CategoryUpdate {
		t.Fatalf("bash = %+v", bash)
	}
	curl := findPatch(st.Pending, "dnf:curl-minimal.aarch64")
	if curl == nil || curl.Category != CategorySecurity || curl.Severity != SeverityImportant {
		t.Fatalf("curl = %+v", curl)
	}
	if st.LastInstallAt == nil || st.LastInstallAt.Unix() != 1731000000 {
		t.Fatalf("lastInstallAt = %v", st.LastInstallAt)
	}
	if got := rec.Lines()[0]; got != "/fake/bin/dnf -q check-update --refresh" {
		t.Fatalf("first command = %s", got)
	}
	// dnf error (exit 1): reported in scanError, nothing pending.
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply {
		return swtest.Reply{Exit: 1, Stderr: "Error: Failed to download metadata for repo 'baseos'"}
	}}
	plat = rec.Platform(nil)
	st = NewScannerWith(plat, &DnfProvider{Plat: plat, Lookup: swtest.Lookup("dnf")}).Collect(context.Background())
	if len(st.Pending) != 0 || !strings.Contains(st.ScanError, "Failed to download metadata") {
		t.Fatalf("dnf error: %+v", st)
	}
}

func TestScannerNoLinuxManager(t *testing.T) {
	rec := &swtest.Recorder{}
	plat := rec.Platform(nil)
	st := NewScannerWith(plat, &AptProvider{Plat: plat, Lookup: swtest.Lookup()}, &DnfProvider{Plat: plat, Lookup: swtest.Lookup()}).Collect(context.Background())
	if strings.Join(st.Unsupported, ",") != "apt,dnf" || st.Pending == nil || len(rec.Calls()) != 0 {
		t.Fatalf("state = %+v", st)
	}
}

func TestScannerMacOS(t *testing.T) {
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		line := c.Line()
		switch {
		case strings.HasSuffix(line, "softwareupdate --list"):
			return swtest.Reply{Stdout: fixture(t, "softwareupdate_list_new.txt")}
		case strings.Contains(line, "brew update"):
			return swtest.Reply{}
		case strings.Contains(line, "brew outdated --json=v2"):
			return swtest.Reply{Stdout: fixture(t, "brew_outdated_v2.json")}
		}
		return swtest.Reply{Exit: 1}
	}}
	plat := rec.Platform(alice)
	brew := &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return true }}
	s := NewScannerWith(plat, &SoftwareUpdateProvider{Plat: plat, Lookup: swtest.Lookup("softwareupdate")}, &BrewProvider{Brew: brew})
	st := s.Collect(context.Background())
	if st.ScanError != "" || len(st.Unsupported) != 0 {
		t.Fatalf("state = %+v", st)
	}
	osu := findPatch(st.Pending, "softwareupdate:macOS@20Sonoma@2014.6.1-23G93")
	if osu == nil || osu.Title != "macOS Sonoma 14.6.1" || osu.NewVersion != "14.6.1" || osu.RequiresReboot == nil || !*osu.RequiresReboot || osu.SizeBytes == nil {
		t.Fatalf("macOS update = %+v", osu)
	}
	cask := findPatch(st.Pending, "brew:libreoffice")
	if cask == nil || cask.Source != SourceBrew || cask.CurrentVersion != "26.2.3" || cask.NewVersion != "26.8.2" {
		t.Fatalf("cask = %+v", cask)
	}
	for _, c := range rec.Calls() {
		isBrew := strings.HasSuffix(c.Path, "brew")
		if isBrew != (c.AsUser != nil) {
			t.Fatalf("wrong account for %s (AsUser %v)", c.Line(), c.AsUser)
		}
	}
	// Nobody logged in: Homebrew is unsupported for this scan and never runs as root.
	rec2 := &swtest.Recorder{Respond: rec.Respond}
	plat2 := rec2.Platform(nil)
	brew2 := &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat2, IsRoot: func() bool { return true }}
	st = NewScannerWith(plat2, &SoftwareUpdateProvider{Plat: plat2, Lookup: swtest.Lookup("softwareupdate")}, &BrewProvider{Brew: brew2}).Collect(context.Background())
	if strings.Join(st.Unsupported, ",") != "brew" || len(st.Pending) != 4 {
		t.Fatalf("no user: %+v", st)
	}
	for _, c := range rec2.Calls() {
		if strings.HasSuffix(c.Path, "brew") {
			t.Fatalf("brew ran without a user: %s", c.Line())
		}
	}
	// Homebrew not installed: silently absent.
	st = NewScannerWith(plat2, &SoftwareUpdateProvider{Plat: plat2, Lookup: swtest.Lookup("softwareupdate")}, &BrewProvider{Brew: &software.Brew{Plat: plat2}}).Collect(context.Background())
	if len(st.Unsupported) != 0 {
		t.Fatalf("absent brew: %v", st.Unsupported)
	}
}

func TestScannerWindows(t *testing.T) {
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "powershell") {
			return swtest.Reply{Stdout: fixture(t, "wua_scan.json")}
		}
		return swtest.Reply{Stdout: wingetFixture(t, "winget_upgrade.txt")}
	}}
	plat := rec.Platform(nil)
	s := NewScannerWith(plat, &WUAProvider{Plat: plat, Lookup: swtest.Lookup("powershell", "winget")}, &WingetProvider{Plat: plat, Lookup: swtest.Lookup("powershell", "winget")})
	st := s.Collect(context.Background())
	if st.ScanError != "" || len(st.Unsupported) != 0 || !st.RebootRequired {
		t.Fatalf("state = %+v", st)
	}
	var wua, wg int
	for _, p := range st.Pending {
		switch p.Source {
		case SourceWUA:
			wua++
		case SourceWinget:
			wg++
		}
	}
	// Four valid WUA updates; winget: three upgrades plus the one that needs explicit targeting.
	if wua != 4 || wg != 4 {
		t.Fatalf("wua %d, winget %d: %+v", wua, wg, st.Pending)
	}
	vc := findPatch(st.Pending, "winget:Microsoft.VCRedist.2015+.x64")
	if vc == nil || vc.CurrentVersion != "14.40.33810.0" || vc.NewVersion != "14.42.34433.0" {
		t.Fatalf("vcredist = %+v", vc)
	}
	ps := rec.Calls()[0]
	if strings.Join(ps.Args, " ") != "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -" || ps.Stdin != strings.TrimRight(wuaScanScript, "\r\n")+"\n\n" {
		t.Fatalf("powershell call = %+v", ps)
	}
	if got := rec.Lines()[1]; got != "/fake/bin/winget upgrade --accept-source-agreements --disable-interactivity" {
		t.Fatalf("winget command = %s", got)
	}
	// winget unavailable to LocalSystem: listed as unsupported, WUA still works.
	st = NewScannerWith(plat, &WUAProvider{Plat: plat, Lookup: swtest.Lookup("powershell")}, &WingetProvider{Plat: plat, Lookup: swtest.Lookup("powershell")}).Collect(context.Background())
	if strings.Join(st.Unsupported, ",") != "winget" || len(st.Pending) != 4 {
		t.Fatalf("no winget: %+v", st)
	}
	// WUA search error.
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply {
		return swtest.Reply{Stdout: fixture(t, "wua_scan_error.json"), Exit: 1}
	}}
	plat = rec.Platform(nil)
	st = NewScannerWith(plat, &WUAProvider{Plat: plat, Lookup: swtest.Lookup("powershell")}).Collect(context.Background())
	if !strings.Contains(st.ScanError, "0x8024402C") || len(st.Pending) != 0 {
		t.Fatalf("WUA error: %+v", st)
	}
}

func TestNormalizePendingBounds(t *testing.T) {
	var in []protocol.PendingPatch
	for i := 0; i < MaxPending+100; i++ {
		id, _ := EncodeID(SourceApt, "pkg"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+"-"+strings.Repeat("1", i%5)+"-"+itoa(i))
		in = append(in, protocol.PendingPatch{ID: id, Source: SourceApt})
	}
	in = append(in, protocol.PendingPatch{ID: in[0].ID, Source: SourceApt}, protocol.PendingPatch{ID: "bad id", Source: SourceApt})
	out := normalizePending(in)
	if len(out) != MaxPending {
		t.Fatalf("len = %d", len(out))
	}
	seen := map[string]bool{}
	for _, p := range out {
		if seen[p.ID] || p.Title == "" {
			t.Fatalf("duplicate or untitled %+v", p)
		}
		seen[p.ID] = true
	}
}

func itoa(i int) string {
	return strings.TrimLeft(strings.Replace(time.Duration(i).String(), "ns", "", 1), "0")
}

// ---- patch.install ----

type fakeScheduler struct {
	mu    sync.Mutex
	plans []reboot.Plan
}

func (f *fakeScheduler) Schedule(p reboot.Plan) (<-chan struct{}, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans = append(f.plans, p)
	ch := make(chan struct{})
	close(ch)
	return ch, true
}

func (f *fakeScheduler) snapshot() []reboot.Plan {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reboot.Plan(nil), f.plans...)
}

func runInstall(t *testing.T, h *InstallHandler, plat platform.Platform, spec any) (jobs.Result, *swtest.Job) {
	t.Helper()
	job := swtest.NewJob(context.Background(), plat, t.TempDir(), spec)
	return h.Handle(job.JobContext), job
}

func installResult(t *testing.T, res jobs.Result) protocol.PatchInstallResult {
	t.Helper()
	r, ok := res.Result.(protocol.PatchInstallResult)
	if !ok {
		t.Fatalf("result is %T, status %s: %s", res.Result, res.Status, res.Message)
	}
	return r
}

// aptWorld simulates an apt system with upgradable packages.
func aptWorld(t *testing.T, pending map[string]bool, failInstall bool) *swtest.Recorder {
	var mu sync.Mutex
	return &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		mu.Lock()
		defer mu.Unlock()
		line := c.Line()
		switch {
		case strings.Contains(line, "--only-upgrade"):
			if failInstall {
				return swtest.Reply{Exit: 100, Stderr: "E: Sub-process /usr/bin/dpkg returned an error code (1)\n"}
			}
			i := 0
			for i < len(c.Args) && c.Args[i] != "--" {
				i++
			}
			for _, n := range c.Args[i+1:] {
				delete(pending, n)
			}
			return swtest.Reply{Stdout: "Unpacking ...\n"}
		case strings.HasSuffix(line, "list --upgradable"):
			var b strings.Builder
			b.WriteString("Listing...\n")
			for n := range pending {
				b.WriteString(n + "/stable-security 2.0 arm64 [upgradable from: 1.0]\n")
			}
			return swtest.Reply{Stdout: b.String()}
		}
		return swtest.Reply{}
	}}
}

func aptHandler(plat platform.Platform, sched RebootScheduler) *InstallHandler {
	s := NewScannerWith(plat, &AptProvider{Plat: plat, Lookup: swtest.Lookup("apt-get", "apt")}, &DnfProvider{Plat: plat, Lookup: swtest.Lookup("apt-get", "apt")})
	return &InstallHandler{Scanner: s, Scheduler: sched, OSName: "Linux"}
}

func TestPatchInstallSelectedApt(t *testing.T) {
	pending := map[string]bool{"libssl3": true, "openssl": true, "curl": true}
	rec := aptWorld(t, pending, false)
	plat := rec.Platform(nil)
	sched := &fakeScheduler{}
	res, job := runInstall(t, aptHandler(plat, sched), plat, protocol.PatchInstallSpec{
		UpdateIDs: []string{"apt:openssl", "apt:libssl3", "apt:not-pending", "dnf:bash.x86_64", "wua:3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11"},
		Reboot:    protocol.RebootPolicy{Mode: RebootNever},
	})
	r := installResult(t, res)
	if res.Status != protocol.StatusFailed || len(r.Installed) != 5 {
		t.Fatalf("status %s: %+v", res.Status, r)
	}
	got := map[string]protocol.PatchInstallItem{}
	for _, it := range r.Installed {
		got[it.ID] = it
	}
	if !got["apt:openssl"].OK || !got["apt:libssl3"].OK {
		t.Fatalf("installed items = %+v", r.Installed)
	}
	// Never pending: reported as such and never handed to apt-get.
	if it := got["apt:not-pending"]; it.OK || !strings.Contains(it.Error, "not pending") {
		t.Fatalf("not pending: %+v", it)
	}
	// dnf is a Linux source, but not installed on this (apt) machine.
	if it := got["dnf:bash.x86_64"]; it.OK || !strings.Contains(it.Error, "dnf cannot be used") {
		t.Fatalf("foreign source: %+v", it)
	}
	if it := got["wua:3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11"]; it.OK || !strings.HasPrefix(it.Error, "not supported on this OS") {
		t.Fatalf("wua on linux: %+v", it)
	}
	// Order of the result follows the request.
	if r.Installed[0].ID != "apt:openssl" || r.Installed[1].ID != "apt:libssl3" {
		t.Fatalf("order = %+v", r.Installed)
	}
	var install string
	for _, l := range rec.Lines() {
		if strings.Contains(l, "--only-upgrade") {
			install = l
		}
	}
	if install != "/fake/bin/apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=120 install --only-upgrade -- openssl libssl3" {
		t.Fatalf("install command = %q", install)
	}
	if !strings.Contains(job.Out.String(), "Unpacking") {
		t.Fatalf("output not streamed: %q", job.Out.String())
	}
	// Policy never: nothing scheduled, even after After runs.
	res.After()
	if len(sched.snapshot()) != 0 {
		t.Fatal("mode never scheduled a restart")
	}
}

func TestPatchInstallAllAndFailures(t *testing.T) {
	pending := map[string]bool{"libssl3": true, "openssl": true}
	rec := aptWorld(t, pending, false)
	plat := rec.Platform(nil)
	res, _ := runInstall(t, aptHandler(plat, &fakeScheduler{}), plat, protocol.PatchInstallSpec{UpdateIDs: nil, Sources: []string{"apt"}})
	r := installResult(t, res)
	if res.Status != protocol.StatusSucceeded || len(r.Installed) != 2 || !r.Installed[0].OK || !r.Installed[1].OK {
		t.Fatalf("all: status %s (%s) %+v", res.Status, res.Message, r)
	}
	// Nothing pending: succeeded with an empty list (not null).
	res, _ = runInstall(t, aptHandler(plat, &fakeScheduler{}), plat, protocol.PatchInstallSpec{Sources: []string{"apt"}})
	r = installResult(t, res)
	if res.Status != protocol.StatusSucceeded || r.Installed == nil || len(r.Installed) != 0 || res.Message != "no pending updates" {
		t.Fatalf("nothing pending: %s %q %+v", res.Status, res.Message, r)
	}
	// The tool fails: every requested update fails with the exit code.
	pending = map[string]bool{"libssl3": true}
	rec = aptWorld(t, pending, true)
	plat = rec.Platform(nil)
	res, _ = runInstall(t, aptHandler(plat, &fakeScheduler{}), plat, protocol.PatchInstallSpec{UpdateIDs: []string{"apt:libssl3"}})
	r = installResult(t, res)
	if res.Status != protocol.StatusFailed || r.Installed[0].OK || !strings.Contains(r.Installed[0].Error, "code 100") {
		t.Fatalf("failing tool: %+v", r)
	}
	// Only foreign sources: unsupported.
	res, _ = runInstall(t, aptHandler(plat, &fakeScheduler{}), plat, protocol.PatchInstallSpec{Sources: []string{"wua", "winget"}})
	if res.Status != protocol.StatusUnsupported {
		t.Fatalf("foreign sources: %s", res.Status)
	}
	res, _ = runInstall(t, aptHandler(plat, &fakeScheduler{}), plat, protocol.PatchInstallSpec{UpdateIDs: []string{"wua:3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11"}})
	if res.Status != protocol.StatusUnsupported {
		t.Fatalf("foreign ids: %s", res.Status)
	}
}

func TestPatchInstallValidation(t *testing.T) {
	rec := &swtest.Recorder{}
	plat := rec.Platform(nil)
	h := aptHandler(plat, &fakeScheduler{})
	tooMany := make([]string, MaxUpdateIDs+1)
	for i := range tooMany {
		tooMany[i] = "apt:x"
	}
	for name, spec := range map[string]any{
		"injection":          protocol.PatchInstallSpec{UpdateIDs: []string{"apt:x; rm -rf /"}},
		"option":             protocol.PatchInstallSpec{UpdateIDs: []string{"-o Foo"}},
		"subshell":           protocol.PatchInstallSpec{UpdateIDs: []string{"$(id)"}},
		"empty id":           protocol.PatchInstallSpec{UpdateIDs: []string{""}},
		"too many":           protocol.PatchInstallSpec{UpdateIDs: tooMany},
		"unknown source":     protocol.PatchInstallSpec{Sources: []string{"yum"}},
		"all without srcs":   protocol.PatchInstallSpec{},
		"mode":               protocol.PatchInstallSpec{Sources: []string{"apt"}, Reboot: protocol.RebootPolicy{Mode: "later"}},
		"deferrals":          protocol.PatchInstallSpec{Sources: []string{"apt"}, Reboot: protocol.RebootPolicy{Mode: "force", Deferrals: -1}},
		"many deferrals":     protocol.PatchInstallSpec{Sources: []string{"apt"}, Reboot: protocol.RebootPolicy{Mode: "force", Deferrals: 100}},
		"deadline":           protocol.PatchInstallSpec{Sources: []string{"apt"}, Reboot: protocol.RebootPolicy{Mode: "force", DeadlineMinutes: -5}},
		"long deadline":      protocol.PatchInstallSpec{Sources: []string{"apt"}, Reboot: protocol.RebootPolicy{Mode: "force", DeadlineMinutes: MaxDeadlineMinutes + 1}},
		"message option":     protocol.PatchInstallSpec{Sources: []string{"apt"}, Reboot: protocol.RebootPolicy{Mode: "force", Message: "-h now"}},
		"message control":    protocol.PatchInstallSpec{Sources: []string{"apt"}, Reboot: protocol.RebootPolicy{Mode: "force", Message: "a\nb"}},
		"ids wrong type":     `{"updateIds":"apt:x"}`,
		"sources wrong type": `{"updateIds":null,"sources":"apt"}`,
	} {
		res, _ := runInstall(t, h, plat, spec)
		if res.Status != protocol.StatusRejected {
			t.Errorf("%s: status %s", name, res.Status)
		}
	}
	if len(rec.Calls()) != 0 {
		t.Fatalf("commands were run: %v", rec.Lines())
	}
	// Names that decode but are not valid for the tool never reach it.
	rec = aptWorld(t, map[string]bool{}, false)
	plat = rec.Platform(nil)
	res, _ := runInstall(t, aptHandler(plat, &fakeScheduler{}), plat, protocol.PatchInstallSpec{UpdateIDs: []string{"apt:Bad_Name", "apt:x@20y"}})
	r := installResult(t, res)
	if len(r.Installed) != 2 || r.Installed[0].OK || r.Installed[1].OK {
		t.Fatalf("invalid names: %+v", r)
	}
	for _, l := range rec.Lines() {
		if strings.Contains(l, "--only-upgrade") {
			t.Fatalf("invalid name reached apt-get: %s", l)
		}
	}
}

func TestPatchInstallRebootPolicy(t *testing.T) {
	run := func(mode string, rebootPending bool) ([]reboot.Plan, jobs.Result) {
		rec := aptWorld(t, map[string]bool{"openssl": true}, false)
		plat := rec.Platform(alice)
		plat.Reboot = rebootPending
		sched := &fakeScheduler{}
		refreshed := 0
		h := aptHandler(plat, sched)
		h.AfterInstall = func() { refreshed++ }
		res, _ := runInstall(t, h, plat, protocol.PatchInstallSpec{
			UpdateIDs: []string{"apt:openssl"},
			Reboot:    protocol.RebootPolicy{Mode: mode, NotifyUser: true, Deferrals: 2, DeadlineMinutes: 120, Message: "Updates from Example IT."},
		})
		if len(sched.snapshot()) != 0 {
			t.Fatalf("%s: the restart was scheduled before the result was sent", mode)
		}
		if res.After == nil {
			t.Fatalf("%s: no After hook", mode)
		}
		res.After()
		if refreshed != 1 {
			t.Fatalf("%s: patch state not refreshed after the installation", mode)
		}
		return sched.snapshot(), res
	}
	// never: report only, even when a restart is required.
	plans, res := run(RebootNever, true)
	if len(plans) != 0 || !installResult(t, res).RebootRequired || !strings.Contains(res.Message, "restart required") {
		t.Fatalf("never: %v %q", plans, res.Message)
	}
	// if_required without a pending restart: nothing.
	if plans, _ = run(RebootIfRequired, false); len(plans) != 0 {
		t.Fatalf("if_required, not required: %v", plans)
	}
	// if_required with a pending restart: scheduled with the policy's values.
	plans, res = run(RebootIfRequired, true)
	if len(plans) != 1 || !strings.Contains(res.Message, "restart scheduled") {
		t.Fatalf("if_required: %v %q", plans, res.Message)
	}
	if p := plans[0]; !p.NotifyUser || p.Deferrals != 2 || p.Deadline != 2*time.Hour || p.Message != "Updates from Example IT." {
		t.Fatalf("plan = %+v", p)
	}
	// force: always.
	if plans, _ = run(RebootForce, false); len(plans) != 1 {
		t.Fatalf("force: %v", plans)
	}
}

// End to end with the real scheduler, a fake UI and a fake rebooter:
// if_required with deferrals, the user postpones, the restart happens at the deadline.
func TestPatchInstallWithRealScheduler(t *testing.T) {
	rec := aptWorld(t, map[string]bool{"openssl": true}, false)
	plat := rec.Platform(alice)
	plat.Reboot = true
	ui := userui.NewFake()
	ui.Answer = false
	rb := &countingRebooter{ch: make(chan time.Time, 4)}
	sched := reboot.NewScheduler(ui, rb, plat, nil)
	sched.StartDelay, sched.FinalWarning, sched.AskTimeout = 10*time.Millisecond, 0, time.Second
	h := aptHandler(plat, sched)
	res, _ := runInstall(t, h, plat, protocol.PatchInstallSpec{UpdateIDs: []string{"apt:openssl"}, Reboot: protocol.RebootPolicy{Mode: RebootIfRequired, NotifyUser: true, Deferrals: 1}})
	start := time.Now()
	res.After()
	select {
	case at := <-rb.ch:
		if at.Sub(start) > 5*time.Second {
			t.Fatalf("restart after %v", at.Sub(start))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no restart")
	}
	// Deadline 0 minutes: no prompt is shown even with a deferral.
	if _, q, _, _ := ui.Snapshot(); len(q) != 0 {
		t.Fatalf("prompts = %d", len(q))
	}
}

type countingRebooter struct{ ch chan time.Time }

func (c *countingRebooter) Reboot(context.Context, time.Duration, string) error {
	c.ch <- time.Now()
	return nil
}

func TestSoftwareUpdateInstall(t *testing.T) {
	var restartArgs []string
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		switch {
		case c.Args[0] == "--list":
			return swtest.Reply{Stdout: fixture(t, "softwareupdate_list_new.txt")}
		case len(c.Args) == 2 && c.Args[1] == "macOS Sonoma 14.6.1-23G93":
			// Apple Silicon without a volume owner.
			return swtest.Reply{Stdout: "Downloading macOS Sonoma 14.6.1\nPassword:\n", Stderr: "Failed to authenticate\n", Exit: 0}
		case len(c.Args) == 2 && c.Args[1] == "Safari17.6SonomaAuto-17.6":
			return swtest.Reply{Stdout: "Downloading Safari\nInstalling Safari\nDone.\n"}
		case c.Args[len(c.Args)-1] == "--restart":
			restartArgs = c.Args
		}
		return swtest.Reply{}
	}}
	plat := rec.Platform(alice)
	p := &SoftwareUpdateProvider{Plat: plat, Lookup: swtest.Lookup("softwareupdate")}
	out, err := p.Install(context.Background(), InstallRequest{Names: []string{"macOS Sonoma 14.6.1-23G93", "Safari17.6SonomaAuto-17.6", "Not Listed-1.0", "-bad"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]protocol.PatchInstallItem{}
	for _, it := range out.Items {
		got[it.ID] = it
	}
	if it := got["softwareupdate:macOS@20Sonoma@2014.6.1-23G93"]; it.OK || !strings.Contains(it.Error, "volume owner") {
		t.Fatalf("macOS update must fail clearly: %+v", it)
	}
	if !got["softwareupdate:Safari17.6SonomaAuto-17.6"].OK {
		t.Fatalf("safari: %+v", out.Items)
	}
	if it := got["softwareupdate:Not@20Listed-1.0"]; it.OK || !strings.Contains(it.Error, "not pending") {
		t.Fatalf("not listed: %+v", it)
	}
	if it := got["softwareupdate:-bad"]; it.OK {
		t.Fatalf("invalid label: %+v", out.Items)
	}
	for _, l := range rec.Lines() {
		if strings.Contains(l, "--restart") || strings.Contains(l, "-bad") {
			t.Fatalf("unexpected command %s", l)
		}
	}
	// A restart-requiring update that installs is finished by softwareupdate's own restart.
	rec2 := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if c.Args[0] == "--list" {
			return swtest.Reply{Stdout: fixture(t, "softwareupdate_list_new.txt")}
		}
		if c.Args[len(c.Args)-1] == "--restart" {
			restartArgs = c.Args
		}
		return swtest.Reply{Stdout: "Done.\n"}
	}}
	p = &SoftwareUpdateProvider{Plat: rec2.Platform(alice), Lookup: swtest.Lookup("softwareupdate")}
	out, err = p.Install(context.Background(), InstallRequest{Names: []string{"macOS Sonoma 14.6.1-23G93"}})
	if err != nil || !out.RebootRequired || out.Restart == nil || !out.Items[0].OK {
		t.Fatalf("restart update: %+v %v", out, err)
	}
	if err := out.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(restartArgs, "|") != "--install|macOS Sonoma 14.6.1-23G93|--restart" {
		t.Fatalf("restart args = %q", restartArgs)
	}
}

func TestBrewAndWingetInstall(t *testing.T) {
	outdated := map[string]bool{"wget": true, "jq": true}
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		switch c.Args[0] {
		case "upgrade":
			for _, n := range c.Args[2:] {
				if n != "jq" {
					delete(outdated, n)
				}
			}
			return swtest.Reply{Exit: 1, Stderr: "Error: jq: failed\n"}
		case "outdated":
			var parts []string
			for n := range outdated {
				parts = append(parts, `{"name":"`+n+`","installed_versions":["1"],"current_version":"2","pinned":false}`)
			}
			return swtest.Reply{Stdout: `{"formulae":[` + strings.Join(parts, ",") + `],"casks":[]}`}
		}
		return swtest.Reply{}
	}}
	plat := rec.Platform(alice)
	p := &BrewProvider{Brew: &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return true }}}
	out, err := p.Install(context.Background(), InstallRequest{Names: []string{"wget", "jq", "https://evil/x.rb"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]protocol.PatchInstallItem{}
	for _, it := range out.Items {
		got[it.ID] = it
	}
	if !got["brew:wget"].OK || got["brew:jq"].OK || len(out.Items) != 3 {
		t.Fatalf("brew items = %+v", out.Items)
	}
	for _, c := range rec.Calls() {
		if c.AsUser == nil {
			t.Fatalf("brew ran as root: %s", c.Line())
		}
		if c.Args[0] == "upgrade" && strings.Join(c.Args, " ") != "upgrade -- wget jq" {
			t.Fatalf("upgrade args = %v", c.Args)
		}
	}
	// winget: one exact id per call.
	rec = &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if len(c.Args) < 4 {
			return swtest.Reply{Stdout: wingetFixture(t, "winget_upgrade.txt")}
		}
		if c.Args[3] == "Git.Git" {
			return swtest.Reply{Exit: -1978335189}
		}
		return swtest.Reply{}
	}}
	w := &WingetProvider{Plat: rec.Platform(nil), Lookup: swtest.Lookup("winget")}
	out, err = w.Install(context.Background(), InstallRequest{Names: []string{"7zip.7zip", "Git.Git", "a/b", "Not.Pending"}})
	if err != nil || len(out.Items) != 4 {
		t.Fatalf("winget: %+v %v", out, err)
	}
	if got := rec.Lines(); len(got) != 3 || got[1] != "/fake/bin/winget upgrade -e --id 7zip.7zip --silent --accept-package-agreements --accept-source-agreements --disable-interactivity" {
		t.Fatalf("winget commands: %v", got)
	}
	// The invalid id is reported first, then one result per winget call.
	if out.Items[0].ID != "winget:a/b" || out.Items[0].OK || out.Items[1].ID != "winget:Not.Pending" || out.Items[1].OK ||
		!out.Items[2].OK || out.Items[3].OK || !strings.Contains(out.Items[3].Error, "winget exited") {
		t.Fatalf("winget items: %+v", out.Items)
	}
}

func TestWUAInstallRequest(t *testing.T) {
	rec := &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply { return swtest.Reply{Stdout: fixture(t, "wua_install.json")} }}
	p := &WUAProvider{Plat: rec.Platform(nil), Lookup: swtest.Lookup("powershell")}
	out, err := p.Install(context.Background(), InstallRequest{Names: []string{"3F0A2D6C-1B7E-4C55-9E0A-6D2C9B1F7A11", "11111111-2222-3333-4444-555555555555", "not-a-guid"}})
	if err != nil {
		t.Fatal(err)
	}
	c := rec.Calls()[0]
	if c.Stdin != strings.TrimRight(wuaInstallScript, "\r\n")+"\n\n" || !c.HasEnv("DRANZO_WUA_ALL=0") || !c.HasEnv("DRANZO_WUA_IDS=3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11,11111111-2222-3333-4444-555555555555") {
		t.Fatalf("call = %+v", c)
	}
	if !out.RebootRequired || len(out.Items) != 4 || out.Items[0].OK {
		t.Fatalf("items = %+v", out.Items)
	}
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply {
		return swtest.Reply{Stdout: `{"ok":true,"results":[],"rebootRequired":false}`}
	}}
	p = &WUAProvider{Plat: rec.Platform(nil), Lookup: swtest.Lookup("powershell")}
	if _, err := p.Install(context.Background(), InstallRequest{All: true}); err != nil || !rec.Calls()[0].HasEnv("DRANZO_WUA_ALL=1") {
		t.Fatalf("all: %v %+v", err, rec.Calls())
	}
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply { return swtest.Reply{Err: errors.New("boom")} }}
	p = &WUAProvider{Plat: rec.Platform(nil), Lookup: swtest.Lookup("powershell")}
	if _, err := p.Install(context.Background(), InstallRequest{All: true}); err == nil {
		t.Fatal("run error swallowed")
	}
}
