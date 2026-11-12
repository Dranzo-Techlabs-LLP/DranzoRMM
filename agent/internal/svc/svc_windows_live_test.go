//go:build windows

package svc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	winsvc "golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/dranzo/dranzormm/agent/internal/config"
)

// Live Windows service test (DRANZO_REAL_WINDOWS=1 and
// DRANZO_REAL_WINDOWS_SERVICE=1, run by the Windows verification kit,
// scripts/windows-kit). It registers a THROWAWAY service, "DranzoRMMAgentTest",
// through the real code (kardianos/service + SCM), whose program is this test
// binary acting as a minimal service host (TestWindowsLiveServiceHost). The
// real "DranzoRMMAgent" service is never touched. Everything is removed at
// the end, also when the test fails.

const testServiceName = "DranzoRMMAgentTest"

var (
	serviceHost   = flag.Bool("dranzo.service-host", false, "run as the service host of TestWindowsLiveService (set by the test itself)")
	serviceMarker = flag.String("dranzo.service-marker", "", "marker file of the service host")
	serviceData   = flag.String("dranzo.service-data", "", "throwaway data directory of the service host")
)

func requireServiceTest(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" || os.Getenv("DRANZO_REAL_WINDOWS_SERVICE") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 and DRANZO_REAL_WINDOWS_SERVICE=1 to register a throwaway Windows service")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("the service test needs an elevated Administrator prompt")
	}
}

func appendMarker(path, line string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "%s %d\n", line, os.Getpid())
	_ = f.Close()
}

// TestWindowsLiveServiceHost is the program of the throwaway service. It is
// only ever started by the Service Control Manager with -dranzo.service-host.
//
// Requests from the test arrive as files next to the marker:
// <marker>.crash makes the run function fail (the process exits with code 1,
// so the SCM recovery action must restart it); <marker>.selfuninstall runs
// SelfUninstall from inside the service, like the agent.uninstall job.
func TestWindowsLiveServiceHost(t *testing.T) {
	if !*serviceHost {
		t.Skip("service host: only started by the Service Control Manager in TestWindowsLiveService")
	}
	serviceName = testServiceName
	marker := *serviceMarker
	err := Run(func(ctx context.Context) error {
		appendMarker(marker, "started")
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				appendMarker(marker, "stopped")
				return nil
			case <-tick.C:
			}
			if os.Remove(marker+".crash") == nil {
				appendMarker(marker, "crashing")
				return errors.New("crash requested by the test")
			}
			if os.Remove(marker+".selfuninstall") == nil {
				appendMarker(marker, "self-uninstalling")
				go func() {
					err := SelfUninstall(config.ResolvePaths(*serviceData))
					appendMarker(marker, fmt.Sprintf("self-uninstall returned %v", err))
				}()
			}
		}
	}, nil)
	appendMarker(marker, fmt.Sprintf("Run returned %v", err))
}

func readMarker(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// scmState returns the SCM state of the test service, or "gone".
func scmState(t *testing.T) string {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect to the SCM: %v", err)
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(testServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "gone"
	}
	if err != nil {
		return "open failed: " + err.Error()
	}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil {
		return "query failed: " + err.Error()
	}
	switch st.State {
	case winsvc.Running:
		return "running"
	case winsvc.Stopped:
		return "stopped"
	case winsvc.StartPending:
		return "start pending"
	case winsvc.StopPending:
		return "stop pending"
	}
	return fmt.Sprintf("state %d", st.State)
}

// forceRemove deletes the throwaway service whatever state it is in.
func forceRemove(t *testing.T) {
	m, err := mgr.Connect()
	if err != nil {
		t.Logf("cleanup: connect: %v", err)
		return
	}
	defer func() { _ = m.Disconnect() }()
	if s, err := m.OpenService(testServiceName); err == nil {
		_, _ = s.Control(winsvc.Stop)
		time.Sleep(time.Second)
		if err := s.Delete(); err != nil {
			t.Logf("cleanup: delete: %v", err)
		}
		_ = s.Close()
	}
	_ = eventlog.Remove(testServiceName)
}

func eventSourceExists() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\EventLog\Application\`+testServiceName, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

func powershell(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		t.Logf("powershell %q: %v", script, err)
	}
	return strings.TrimSpace(string(out))
}

func TestWindowsLiveService(t *testing.T) {
	requireServiceTest(t)
	orig := serviceName
	serviceName = testServiceName
	t.Cleanup(func() {
		serviceName = orig
		forceRemove(t)
	})
	if Name() != testServiceName || orig != "DranzoRMMAgent" {
		t.Fatalf("service name hook: %q (original %q)", Name(), orig)
	}

	// Leftovers of an aborted earlier run.
	if scmState(t) != "gone" {
		t.Log("removing a leftover test service from an earlier run")
		forceRemove(t)
		waitFor(t, "leftover test service removed", 30*time.Second, func() bool { return scmState(t) == "gone" })
	}

	// Removing a service that does not exist is not an error.
	if err := Uninstall(); err != nil {
		t.Errorf("Uninstall of a missing service: %v", err)
	}
	if st := Status(); st != "not installed" {
		t.Errorf("Status of a missing service: %q", st)
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "marker.txt")
	data := config.ResolvePaths(filepath.Join(dir, "data"))
	if err := data.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(data, &config.Config{ServerURL: "https://rmm.example.com:8443", DeviceID: "dev-svc-live"}); err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestWindowsLiveServiceHost$", "-test.timeout=30m",
		"-dranzo.service-host", "-dranzo.service-marker=" + marker, "-dranzo.service-data=" + data.StateDir}
	if err := Register(args); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := Register(args); err == nil {
		t.Error("registering an existing service succeeded")
	}

	// Configuration as the SCM sees it.
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.OpenService(testServiceName)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SCM config: display=%q start=%d account=%q binary=%q", cfg.DisplayName, cfg.StartType, cfg.ServiceStartName, cfg.BinaryPathName)
	exe, _ := os.Executable()
	if cfg.DisplayName != DisplayName || cfg.Description != Description || cfg.StartType != mgr.StartAutomatic ||
		!strings.Contains(strings.ToLower(cfg.BinaryPathName), strings.ToLower(filepath.Base(exe))) ||
		!strings.EqualFold(cfg.ServiceStartName, "LocalSystem") {
		t.Errorf("service configuration: %+v", cfg)
	}
	actions, err := s.RecoveryActions()
	reset, _ := s.ResetPeriod()
	t.Logf("recovery actions: %+v reset period %d s (err %v)", actions, reset, err)
	if err != nil || len(actions) == 0 || actions[0].Type != mgr.ServiceRestart || actions[0].Delay != 5*time.Second || reset != 3600 {
		t.Errorf("recovery actions: %+v reset %d err %v; want restart after 5s, reset 3600s", actions, reset, err)
	}
	_ = s.Close()
	_ = m.Disconnect()
	if !eventSourceExists() {
		t.Error("event log source not registered")
	}
	// Transparency: the service object grants interactive users read access
	// and carries no deny entries.
	sd := powershell(t, "& \"$env:SystemRoot\\System32\\sc.exe\" sdshow "+testServiceName)
	t.Logf("service security descriptor: %s", sd)
	if strings.Contains(sd, "(D;") {
		t.Errorf("the service object has deny ACEs: %s", sd)
	}

	// Start: the SCM runs the host; Get-Service shows it.
	if err := Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, "service running", 60*time.Second, func() bool { return Status() == "running" })
	waitFor(t, "host started", 30*time.Second, func() bool { return strings.Count(readMarker(marker), "started") >= 1 })
	gs := powershell(t, "Get-Service -Name "+testServiceName+" | ForEach-Object { $_.Status.ToString() + '|' + $_.DisplayName + '|' + $_.StartType.ToString() }")
	t.Logf("Get-Service: %s", gs)
	if !strings.HasPrefix(gs, "Running|"+DisplayName+"|Automatic") {
		t.Errorf("Get-Service: %q", gs)
	}

	// Crash: the process exits with code 1 and the recovery action restarts it.
	if err := os.WriteFile(marker+".crash", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "restart after a crash (recovery action, 5 s)", 90*time.Second, func() bool {
		return strings.Count(readMarker(marker), "started") >= 2
	})
	waitFor(t, "service running again", 30*time.Second, func() bool { return Status() == "running" })
	t.Logf("marker after crash:\n%s", readMarker(marker))

	// Uninstall: stops (graceful: the run function sees its context end) and removes.
	if err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	waitFor(t, "service removed", 60*time.Second, func() bool { return scmState(t) == "gone" })
	if !strings.Contains(readMarker(marker), "stopped") {
		t.Errorf("the host was not stopped gracefully:\n%s", readMarker(marker))
	}
	if eventSourceExists() {
		t.Error("event log source left behind")
	}
	if st := Status(); st != "not installed" {
		t.Errorf("Status after Uninstall: %q", st)
	}
	if gs := powershell(t, "@(Get-Service -Name "+testServiceName+" -ErrorAction SilentlyContinue).Count"); gs != "0" {
		t.Errorf("Get-Service still finds the service: %q", gs)
	}

	// Self-uninstall from inside the running service (agent.uninstall).
	if err := Register(args); err != nil {
		t.Fatalf("Register (second round): %v", err)
	}
	if err := Start(); err != nil {
		t.Fatalf("Start (second round): %v", err)
	}
	waitFor(t, "service running (second round)", 60*time.Second, func() bool { return Status() == "running" })
	if err := os.WriteFile(marker+".selfuninstall", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	waitFor(t, "service removed by SelfUninstall", 90*time.Second, func() bool { return scmState(t) == "gone" })
	t.Logf("self-uninstall took %v; marker:\n%s", time.Since(start).Round(time.Millisecond), readMarker(marker))
	if _, err := os.Stat(data.ConfigFile()); !os.IsNotExist(err) {
		t.Errorf("SelfUninstall left the configuration behind: %v", err)
	}
	if eventSourceExists() {
		t.Error("event log source left behind by SelfUninstall")
	}
}
