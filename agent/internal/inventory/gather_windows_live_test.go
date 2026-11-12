//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Live Windows tests (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit). They only read the system.

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

// runningAsSystem reports whether this process is LocalSystem (the agent's
// service account). Several Win32 calls (WTSQueryUserToken) need it.
func runningAsSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// psOracle runs a short read-only PowerShell command used as an independent
// source of truth.
func psOracle(t *testing.T, script string) string {
	t.Helper()
	ps := os.Getenv("SystemRoot") + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		t.Logf("oracle %q failed: %v", script, err)
	}
	return strings.TrimSpace(strings.TrimPrefix(string(out), "\ufeff"))
}

func TestWindowsLiveInventory(t *testing.T) {
	requireLiveWindows(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := NewCollector(platform.New(), "0.1.0-wintest")
	inv := c.Collect(ctx)
	raw, _ := json.MarshalIndent(inv, "", "  ")
	t.Logf("running as SYSTEM: %v, native arch: %s / %s\ninventory:\n%s",
		runningAsSystem(), os.Getenv("PROCESSOR_ARCHITECTURE"), os.Getenv("PROCESSOR_ARCHITEW6432"), raw)

	missing := map[string]bool{}
	for _, s := range inv.Unsupported {
		missing[s] = true
	}

	host, _ := os.Hostname()
	if inv.Hostname == "" || !strings.EqualFold(inv.Hostname, host) {
		t.Errorf("hostname %q, os.Hostname %q", inv.Hostname, host)
	}
	if inv.MachineID == "" || missing["machineId"] {
		t.Errorf("machine id missing (unsupported=%v)", inv.Unsupported)
	}
	if inv.OS == nil {
		t.Fatalf("OS info missing (unsupported=%v)", inv.Unsupported)
	}
	if inv.OS.Family != protocol.OSWindows || !strings.HasPrefix(inv.OS.Name, "Windows") ||
		!strings.HasPrefix(inv.OS.Kernel, "10.0.") || !strings.Contains(inv.OS.Build, ".") {
		t.Errorf("OS info not well formed: %+v", *inv.OS)
	}
	// The registry says "Windows 10" on Windows 11; the collector must fix it.
	if caption := psOracle(t, "(Get-CimInstance Win32_OperatingSystem).Caption"); caption != "" {
		t.Logf("Win32_OperatingSystem.Caption: %q", caption)
		if strings.Contains(caption, "Windows 11") && !strings.HasPrefix(inv.OS.Name, "Windows 11") {
			t.Errorf("OS name %q but CIM says %q", inv.OS.Name, caption)
		}
	}
	if inv.Arch != "amd64" && inv.Arch != "arm64" {
		t.Errorf("arch %q", inv.Arch)
	}
	if inv.CPU == nil || inv.CPU.LogicalCores < 1 {
		t.Errorf("cpu %+v", inv.CPU)
	}
	if inv.MemoryBytes < 512<<20 {
		t.Errorf("memory %d bytes", inv.MemoryBytes)
	}

	// Hardware identity: present, or listed as unsupported (a VM may have no serial).
	if inv.Manufacturer == "" && inv.Model == "" {
		t.Errorf("neither manufacturer nor model (CIM and the registry fallback both failed)")
	}
	if inv.Serial == "" && !missing["serial"] {
		t.Error("empty serial not listed in unsupported")
	}
	if inv.Serial != "" && missing["serial"] {
		t.Error("serial present and listed as unsupported")
	}
	t.Logf("hardware: manufacturer=%q model=%q serial=%q", inv.Manufacturer, inv.Model, inv.Serial)

	// Disks: at least the system drive, with sane sizes.
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	foundSys := false
	for _, d := range inv.Disks {
		if d.TotalBytes == 0 || d.FreeBytes > d.TotalBytes {
			t.Errorf("disk not well formed: %+v", d)
		}
		if strings.HasPrefix(strings.ToUpper(d.MountPoint), sysDrive) || strings.HasPrefix(strings.ToUpper(d.Device), sysDrive) {
			foundSys = true
		}
	}
	if !foundSys {
		t.Errorf("system drive %s not among the disks %+v", sysDrive, inv.Disks)
	}

	// Network: at least one interface with an address.
	withAddr := 0
	for _, n := range inv.Network {
		if n.Name == "" {
			t.Errorf("interface without a name: %+v", n)
		}
		if len(n.IPv4)+len(n.IPv6) > 0 {
			withAddr++
		}
	}
	if withAddr == 0 {
		t.Errorf("no network interface with an address: %+v", inv.Network)
	}

	// Console user. WTSQueryUserToken needs LocalSystem: as an elevated
	// administrator the collector cannot resolve the user and must say so.
	oracle := psOracle(t, "(Get-CimInstance Win32_ComputerSystem).UserName")
	t.Logf("console user: inventory=%q CIM=%q loggedIn=%v", inv.ConsoleUser, oracle, inv.LoggedInUsers)
	switch {
	case runningAsSystem() && oracle != "":
		if !strings.EqualFold(inv.ConsoleUser, oracle) {
			t.Errorf("console user %q, CIM says %q", inv.ConsoleUser, oracle)
		}
		if len(inv.LoggedInUsers) == 0 {
			t.Error("a user is logged in but loggedInUsers is empty")
		}
	case !runningAsSystem():
		if inv.ConsoleUser == "" && !missing["consoleUser"] && oracle != "" {
			t.Error("console user neither resolved nor listed as unsupported")
		}
		t.Log("not LocalSystem: console user resolution is expected to fail (WTSQueryUserToken needs SeTcbPrivilege); run the kit with -AsSystem for the service view")
	}

	if inv.BootTime == nil || inv.UptimeSeconds == 0 {
		t.Errorf("boot time %v uptime %d", inv.BootTime, inv.UptimeSeconds)
	}
	if missing["pendingReboot"] {
		t.Error("pending reboot unsupported")
	}
	t.Logf("pending reboot: %v", inv.PendingReboot)
	if inv.Timezone == "" {
		t.Error("no time zone")
	}
	if inv.Agent == nil || inv.Agent.RSSBytes == 0 {
		t.Errorf("agent stats %+v", inv.Agent)
	}
	for _, s := range inv.Unsupported {
		switch s {
		case "serial", "consoleUser":
		default:
			t.Errorf("unexpected unsupported section %q", s)
		}
	}

	// The hardware CIM query on its own (the registry fallback hides its failures).
	hw, err := hardwareFromCIM(ctx)
	t.Logf("CIM hardware query: %+v err=%v", hw, err)
	if err != nil {
		t.Errorf("CIM hardware query failed: %v", err)
	}

	// Statistics used by the heartbeat.
	stats := c.SystemStats(ctx)
	t.Logf("system stats: %+v", stats)
}
