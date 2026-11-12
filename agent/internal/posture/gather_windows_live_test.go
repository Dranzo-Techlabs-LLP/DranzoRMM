//go:build windows

package posture

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Live Windows tests (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit). They only read the system.

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

func runningAsSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// psOracle runs a short read-only PowerShell command as an independent check.
func psOracle(t *testing.T, script string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, PowerShellPath(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		t.Logf("oracle %q failed: %v", script, err)
	}
	return strings.TrimSpace(strings.TrimPrefix(string(out), "\ufeff"))
}

// TestWindowsLiveSections runs every sub-collector on its own so that a
// failure shows its error (Collect only lists the section as unsupported).
func TestWindowsLiveSections(t *testing.T) {
	requireLiveWindows(t)
	t.Logf("running as SYSTEM: %v", runningAsSystem())
	t.Logf("cmdlets: Get-MpComputerStatus=%q Get-BitLockerVolume=%q Get-NetFirewallProfile=%q Get-LocalGroupMember=%q",
		psOracle(t, "[bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)"),
		psOracle(t, "[bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)"),
		psOracle(t, "[bool](Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)"),
		psOracle(t, "[bool](Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)"))
	c := New(platform.New(), nil)
	ctx := context.Background()

	t.Run("antivirus", func(t *testing.T) {
		av, err := c.Antivirus(ctx)
		t.Logf("antivirus: %+v err=%v", av, err)
		if err != nil {
			t.Fatal(err)
		}
		if len(av) == 0 {
			t.Fatal("no antivirus product found (Windows always has at least Microsoft Defender registered)")
		}
		for _, p := range av {
			if p.Name == "" || (p.Source != SourceWSC && p.Source != SourceDefender) {
				t.Errorf("product not well formed: %+v", p)
			}
		}
		raw, _ := c.runJSON(ctx, PSAntivirus)
		t.Logf("raw antivirus script output: %s", raw)
	})

	t.Run("firewall", func(t *testing.T) {
		fw, err := c.Firewall(ctx)
		t.Logf("firewall: %+v err=%v", fw, err)
		if err != nil {
			t.Fatal(err)
		}
		if fw == nil || fw.Detail == "" {
			t.Fatalf("firewall not well formed: %+v", fw)
		}
		oracle := psOracle(t, "@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Enabled.ToString() -eq 'True' }).Count")
		t.Logf("enabled firewall profiles (oracle): %s", oracle)
		if oracle == "3" && !fw.Enabled {
			t.Error("all three profiles are on but the firewall is reported off")
		}
	})

	t.Run("bitlocker", func(t *testing.T) {
		vols, err := c.DiskEncryption(ctx)
		t.Logf("disk encryption: %+v err=%v", vols, err)
		if err != nil {
			// Home editions and some VMs have no BitLocker: acceptable, recorded.
			t.Logf("RESULT bitlocker: not available (%v)", err)
			return
		}
		for _, v := range vols {
			if v.Volume == "" || v.Method == "" || v.Status == "" {
				t.Errorf("volume not well formed: %+v", v)
			}
		}
		t.Logf("RESULT bitlocker: %d volume(s)", len(vols))
	})

	t.Run("localadmins", func(t *testing.T) {
		accounts, err := c.LocalAdminAccounts(ctx)
		t.Logf("local admins: %+v err=%v", accounts, err)
		if err != nil {
			t.Fatal(err)
		}
		builtin := psOracle(t, "(Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' } | Select-Object -First 1).Name")
		me := ""
		if !runningAsSystem() {
			me = os.Getenv("USERNAME")
		}
		foundBuiltin, foundMe := false, false
		for _, a := range accounts {
			if a.Name == "" {
				t.Errorf("account without a name: %+v", a)
			}
			n := strings.ToLower(a.Name)
			if i := strings.LastIndexByte(n, '\\'); i >= 0 {
				n = n[i+1:]
			}
			if a.Builtin || (builtin != "" && n == strings.ToLower(builtin)) {
				foundBuiltin = true
			}
			if me != "" && n == strings.ToLower(me) {
				foundMe = true
			}
		}
		t.Logf("built-in administrator (oracle) %q found=%v; current user %q found=%v", builtin, foundBuiltin, me, foundMe)
		if !foundBuiltin && !foundMe {
			t.Error("neither the built-in Administrator nor the current admin user is listed")
		}
	})

	t.Run("screenlock", func(t *testing.T) {
		sl, err := c.ScreenLock(ctx)
		t.Logf("screen lock: %+v err=%v (machine inactivity limit %d s)", sl, err, MachineInactivitySeconds())
		if err == nil && sl == nil {
			t.Fatal("nil screen lock without an error")
		}
		if sl != nil && sl.TimeoutSeconds < 0 {
			t.Errorf("negative timeout %+v", sl)
		}
	})

	t.Run("lastpatch", func(t *testing.T) {
		when, err := c.LastPatchDate(ctx)
		t.Logf("last patch date: %v err=%v", when, err)
		if when != nil && (when.After(time.Now().Add(48*time.Hour)) || when.Year() < 2015) {
			t.Errorf("implausible last patch date %v", when)
		}
	})

	t.Run("ports", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		port := ln.Addr().(*net.TCPAddr).Port
		ports, err := c.ListeningPorts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		withProcess, mine := 0, false
		self := strings.ToLower(filepath.Base(os.Args[0]))
		for _, p := range ports {
			if p.Process != "" {
				withProcess++
			}
			if p.Port == port {
				mine = true
				if !strings.EqualFold(p.Process, self) {
					t.Errorf("own listener %d: process %q, want %q", port, p.Process, self)
				}
			}
		}
		t.Logf("%d listening sockets, %d with a process name; first: %+v", len(ports), withProcess, ports[:min(len(ports), 10)])
		if !mine {
			t.Errorf("own listener on port %d not reported", port)
		}
		if withProcess == 0 {
			t.Error("no listening socket has a process name")
		}
	})
}

// TestWindowsLivePosture runs the whole report the way the agent sends it.
func TestWindowsLivePosture(t *testing.T) {
	requireLiveWindows(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	start := time.Now()
	p := New(platform.New(), nil).Collect(ctx)
	raw, _ := json.MarshalIndent(p, "", "  ")
	t.Logf("posture collected in %v:\n%s", time.Since(start).Round(time.Millisecond), raw)

	missing := map[string]bool{}
	for _, s := range p.Unsupported {
		missing[s] = true
	}
	for section, filled := range map[string]bool{
		SectionAntivirus: p.Antivirus != nil, SectionFirewall: p.Firewall != nil, SectionDiskEncryption: p.DiskEncryption != nil,
		SectionLocalAdmins: p.LocalAdmins != nil, SectionScreenLock: p.ScreenLock != nil, SectionLastPatchDate: p.LastPatchDate != nil,
		SectionListeningPorts: p.ListeningPorts != nil,
	} {
		if filled == missing[section] {
			t.Errorf("%s: filled=%v unsupported=%v", section, filled, missing[section])
		}
	}
	for _, must := range []string{SectionAntivirus, SectionFirewall, SectionLocalAdmins, SectionListeningPorts, SectionPendingReboot} {
		if missing[must] {
			t.Errorf("section %s must be collectable on Windows", must)
		}
	}
	if len(p.LocalAdmins) == 0 {
		t.Error("no local administrators")
	}
}
