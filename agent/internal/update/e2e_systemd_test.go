package update_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
)

const (
	sysdUnit    = "dranzormm-agent"
	sysdProgram = "/opt/dranzormm/dranzo-agent"
	sysdDropIn  = "/etc/systemd/system/" + sysdUnit + ".service.d"
)

func systemctl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("systemctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func dropIn(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(sysdDropIn, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysdDropIn, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	systemctl(t, "daemon-reload")
}

// TestE2ESystemd installs the agent as a real systemd service and updates it.
//
// It installs and removes a system service and writes to /opt, /etc and
// /var/lib: run it only as root inside a disposable machine or container
// that runs systemd, with DRANZO_UPDATE_E2E_SYSTEMD=1.
func TestE2ESystemd(t *testing.T) {
	if os.Getenv("DRANZO_UPDATE_E2E_SYSTEMD") != "1" {
		t.Skip("opt-in: DRANZO_UPDATE_E2E_SYSTEMD=1 (root, systemd, disposable machine)")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("needs Linux and root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatal("systemd is not running")
	}
	bins := e2eBinaries(t)
	srv, err := testserver.New(testserver.Options{HeartbeatSeconds: 15})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	caFile, trustFile, err := srv.WriteInstallerFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	copyExecutable(t, filepath.Join(bins, binName(verOld, "linux")), sysdProgram)
	paths := config.ResolvePaths("")
	defer func() {
		if t.Failed() {
			out, _ := exec.Command("journalctl", "-u", sysdUnit, "--no-pager", "-n", "80").CombinedOutput()
			t.Logf("journal:\n%s", out)
			logTail, _ := exec.Command("tail", "-n", "60", paths.LogFile()).CombinedOutput()
			t.Logf("agent log:\n%s", logTail)
			state, _ := os.ReadFile(filepath.Join(paths.StateDir, "update-state.json"))
			t.Logf("update-state.json: %s", state)
		}
		out, _ := exec.Command(sysdProgram, "uninstall").CombinedOutput()
		t.Logf("uninstall: %s", strings.TrimSpace(string(out)))
		_ = os.RemoveAll(sysdDropIn)
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = os.RemoveAll(filepath.Dir(sysdProgram))
		_ = os.RemoveAll(paths.StateDir)
	}()
	install := exec.Command(sysdProgram, "install", "--server", srv.URL, "--ca-file", caFile, "--trust-file", trustFile)
	install.Env = append(os.Environ(), "DRANZO_ENROLL_TOKEN="+srv.Token)
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	// The unit as installed restarts a failed service after 120 seconds;
	// shorten that so the crash-loop scenarios finish quickly.
	dropIn(t, "10-e2e-restartsec.conf", "[Service]\nRestartSec=2\n")
	t.Logf("unit:\n%s", systemctl(t, "cat", sysdUnit))

	device, err := srv.AwaitDevice(e2eWait)
	if err != nil {
		t.Fatalf("the service did not enroll: %v", err)
	}
	e := &e2e{began: time.Now(), t: t, srv: srv, bins: bins, device: device, exe: sysdProgram, data: paths}
	mainPID := func() string { return systemctl(t, "show", "-p", "MainPID", "--value", sysdUnit) }
	active := func() {
		t.Helper()
		if got := systemctl(t, "is-active", sysdUnit); got != "active" {
			t.Fatalf("service is %s", got)
		}
	}

	// 1. update, wrong hash, rollback of a version that cannot connect.
	pidV1 := mainPID()
	e.updateAndRollback()
	active()
	if pid := mainPID(); pid == pidV1 || pid == "0" {
		t.Fatalf("MainPID is still %s: the service was not restarted by systemd", pid)
	}
	t.Logf("MainPID %s -> %s", pidV1, mainPID())

	// 2. A version that fails during start-up: systemd restarts it, the
	// agent counts its own starts and rolls back on the fourth.
	from := e.offer(verCrash, e.binary(verCrash), nil)
	st := e.status(from, verCrash, protocol.UpdateRolledBack)
	if !strings.Contains(st.Error, "was started 3 times without confirming") {
		t.Fatalf("rollback reason: %q", st.Error)
	}
	e.helloVersion(verNew)
	e.wantInstalled(verNew, "")
	e.wantNoState()
	active()

	// 3. A "binary" that never reaches the agent's code. The agent cannot
	// roll itself back; the guard, run by systemd from the previous binary
	// before every start (the recommended ExecStartPre line), does.
	dropIn(t, "20-e2e-guard.conf", fmt.Sprintf("[Service]\nExecStartPre=-%s.previous update-guard\n", sysdProgram))
	from = e.offer(verGuard, e.binary(verGuard), nil)
	e.status(from, verGuard, protocol.UpdateInstalled)
	e.helloVersion(verGuard)
	e.wantNoState()

	from = e.offer(verTiny, e.binary(verTiny), nil)
	e.status(from, verTiny, protocol.UpdateVerifying)
	st = e.status(from, verTiny, protocol.UpdateRolledBack)
	if !strings.Contains(st.Error, "update guard") {
		t.Fatalf("rollback reason: %q", st.Error)
	}
	e.helloVersion(verGuard)
	e.wantInstalled(verGuard, verGuard)
	e.wantNoState()
	active()
	for _, v := range []string{verNoConnect, verCrash, verTiny} {
		if !strings.Contains(e.failedList(), `"`+v+`"`) {
			t.Errorf("failed-updates.json does not list %s", v)
		}
	}
	// Give systemd a moment: the service must stay up on the restored version.
	time.Sleep(5 * time.Second)
	active()
	t.Logf("failed-updates.json: %s", e.failedList())
}
