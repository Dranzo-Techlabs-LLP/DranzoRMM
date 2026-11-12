//go:build windows

package update

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	winsvc "golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Live Windows tests (run by the Windows verification kit, scripts/windows-kit).
//
//   - DRANZO_REAL_WINDOWS=1: the rename-aside exchange and rollback of a
//     RUNNING executable (a copy of this test binary in a temp directory),
//     and the version probe of the kit's bin\dranzo-agent.exe.
//   - plus DRANZO_REAL_WINDOWS_SERVICE=1: the SCM recovery-action check/set
//     on a throwaway, never-started service "DranzoRMMAgentUpdTest".

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

// TestWindowsLiveSleeperHelper is the process the exchange test runs from
// the copied executable. It does nothing unless started by that test.
func TestWindowsLiveSleeperHelper(t *testing.T) {
	if os.Getenv("DRANZO_LIVE_SLEEPER") != "1" {
		t.Skip("helper process of TestWindowsLiveRenameAsideExchange")
	}
	time.Sleep(3 * time.Minute)
}

func copyExe(t *testing.T, src, dst string, extra []byte) []byte {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, extra...)
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return data
}

func startSleeper(t *testing.T, exe string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(exe, "-test.run=^TestWindowsLiveSleeperHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "DRANZO_LIVE_SLEEPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", exe, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	time.Sleep(time.Second)
	return cmd
}

func alive(cmd *exec.Cmd) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == 259
}

func fileIs(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s has the wrong content (%d bytes, want %d)", path, len(got), len(want))
	}
}

func TestWindowsLiveRenameAsideExchange(t *testing.T) {
	requireLiveWindows(t)
	if !renameAsideDefault {
		t.Fatal("Windows must use the rename-aside strategy")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "dranzo-agent.exe")
	oldBin := copyExe(t, self, exe, []byte("old"))
	running := startSleeper(t, exe)
	if !alive(running) {
		t.Fatal("the copied executable is not running")
	}

	paths := exePaths{exe: exe}
	newBin := copyExe(t, self, paths.staged(), []byte("new-version"))
	t.Logf("staged: %s", paths.staged())

	// Why rename-aside: a running image cannot be replaced or deleted.
	probe := filepath.Join(dir, "probe.exe")
	copyExe(t, self, probe, []byte("probe"))
	if err := os.Rename(probe, exe); err == nil {
		t.Fatal("replacing a running executable succeeded; rename-aside would not be needed")
	} else {
		t.Logf("replacing the running image fails as expected: %v", err)
	}
	if err := os.Remove(exe); err == nil {
		t.Fatal("deleting a running executable succeeded")
	}

	ops := fileOps{paths: paths, renameAside: true}
	if err := ops.exchange(); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	fileIs(t, exe, newBin)
	fileIs(t, paths.previous(), oldBin)
	if _, err := os.Stat(paths.staged()); !os.IsNotExist(err) {
		t.Errorf("staged file still there: %v", err)
	}
	if !alive(running) {
		t.Error("the running old binary died during the exchange")
	}

	// The new binary starts from the executable path (what the SCM does).
	newProc := startSleeper(t, exe)
	if !alive(newProc) {
		t.Fatal("the new binary does not start")
	}

	// Rollback while the failed new binary is still running.
	if err := ops.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	fileIs(t, exe, oldBin)
	fileIs(t, paths.failedAside(), newBin)
	fileIs(t, paths.previous(), oldBin)

	// Everything can be cleaned up once the processes are gone.
	for _, c := range []*exec.Cmd{running, newProc} {
		_ = c.Process.Kill()
		_, _ = c.Process.Wait()
	}
	time.Sleep(500 * time.Millisecond)
	for _, f := range paths.scratch() {
		if err := removeIfExists(f); err != nil {
			t.Errorf("remove %s: %v", f, err)
		}
	}
}

func TestWindowsLiveExchangeWithoutRunningImage(t *testing.T) {
	requireLiveWindows(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "dranzo-agent.exe")
	paths := exePaths{exe: exe}
	if err := os.WriteFile(exe, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.previous(), []byte("v0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.staged(), []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	ops := fileOps{paths: paths, renameAside: true}
	if err := ops.exchange(); err != nil {
		t.Fatalf("exchange over an existing .previous: %v", err)
	}
	fileIs(t, exe, []byte("v2"))
	fileIs(t, paths.previous(), []byte("v1"))
	if err := ops.restore(); err != nil {
		t.Fatal(err)
	}
	fileIs(t, exe, []byte("v1"))
}

// TestWindowsLiveProbeAgentBinary checks the kit's real dranzo-agent.exe the
// way an update checks a staged binary: PE header for this architecture,
// then "dranzo-agent version".
func TestWindowsLiveProbeAgentBinary(t *testing.T) {
	requireLiveWindows(t)
	// Kit layout: <kit>\tests\internal\update\update.test.exe and <kit>\bin\dranzo-agent.exe.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(filepath.Dir(self), "..", "..", "..", "bin", "dranzo-agent.exe")
	if _, err := os.Stat(exe); err != nil {
		t.Skipf("no kit agent binary at %s (run from the Windows verification kit)", exe)
	}
	if err := CheckExecutableFile(exe, runtime.GOOS, runtime.GOARCH); err != nil {
		t.Errorf("CheckExecutableFile(%s, %s): %v", exe, runtime.GOARCH, err)
	}
	other := map[string]string{"amd64": "arm64", "arm64": "amd64"}[runtime.GOARCH]
	if err := CheckExecutableFile(exe, runtime.GOOS, other); err == nil {
		t.Errorf("a %s binary passed the %s check", runtime.GOARCH, other)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	v, err := ProbeVersion(ctx, platform.New(), exe)
	t.Logf("probe: version %q err %v", v, err)
	if err != nil || v == "" {
		t.Fatalf("ProbeVersion: %q %v", v, err)
	}
}

// TestWindowsLiveRecoveryActions checks ensureRestartOnFailure (run by every
// update before the binary is exchanged) against the real SCM.
func TestWindowsLiveRecoveryActions(t *testing.T) {
	requireLiveWindows(t)
	if os.Getenv("DRANZO_REAL_WINDOWS_SERVICE") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS_SERVICE=1 to register a throwaway service")
	}
	const name = "DranzoRMMAgentUpdTest"
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Disconnect() }()
	if old, err := m.OpenService(name); err == nil {
		_ = old.Delete()
		_ = old.Close()
		time.Sleep(2 * time.Second)
	}
	self, _ := os.Executable()
	s, err := m.CreateService(name, self, mgr.Config{
		DisplayName: "DranzoRMM Agent update test (temporary)",
		Description: "Temporary service of the DranzoRMM Windows verification kit; never started; removed by the test.",
		StartType:   mgr.StartDisabled,
	}, "-test.run=^$")
	if err != nil {
		t.Fatalf("create the throwaway service: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Delete(); err != nil {
			t.Errorf("delete the throwaway service: %v", err)
		}
		_ = s.Close()
	})

	hasRestart := func() bool {
		actions, err := s.RecoveryActions()
		if err != nil {
			t.Logf("RecoveryActions: %v", err)
			return false
		}
		for _, a := range actions {
			if a.Type == mgr.ServiceRestart {
				return true
			}
		}
		return false
	}
	if hasRestart() {
		t.Fatal("a new service already has a restart action")
	}
	if err := ensureRestartOnFailure(name); err != nil {
		t.Fatalf("ensureRestartOnFailure on a service without actions: %v", err)
	}
	if !hasRestart() {
		t.Fatal("restart action not set")
	}
	reset, _ := s.ResetPeriod()
	actions, _ := s.RecoveryActions()
	t.Logf("after ensure: %+v reset %d", actions, reset)
	if reset != recoveryResetPeriod || actions[0].Delay != recoveryDelay {
		t.Errorf("recovery %+v reset %d", actions, reset)
	}
	// A "do nothing" action is replaced; an existing restart action is kept.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.NoAction}}, 60); err != nil {
		t.Fatal(err)
	}
	if err := ensureRestartOnFailure(name); err != nil || !hasRestart() {
		t.Fatalf("NoAction not replaced: %v", err)
	}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Minute}}, 60); err != nil {
		t.Fatal(err)
	}
	if err := ensureRestartOnFailure(name); err != nil {
		t.Fatal(err)
	}
	if actions, _ := s.RecoveryActions(); len(actions) != 1 || actions[0].Delay != time.Minute {
		t.Errorf("an existing restart action was changed: %+v", actions)
	}
	// A missing service is an error that names it.
	if err := ensureRestartOnFailure("DranzoRMMAgentDoesNotExist"); err == nil || !strings.Contains(err.Error(), "DranzoRMMAgentDoesNotExist") {
		t.Errorf("missing service: %v", err)
	}
	// Outside the SCM, Prepare does nothing.
	if err := newRestarter(RestartConfig{ServiceName: name}).Prepare(); err != nil {
		t.Errorf("Prepare outside a service: %v", err)
	}
	if isSvc, err := winsvc.IsWindowsService(); err != nil || isSvc {
		t.Errorf("IsWindowsService in a test process: %v %v", isSvc, err)
	}
}
