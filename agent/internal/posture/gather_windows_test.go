//go:build windows

package posture

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// TestWindowsGatherers feeds the fixture output of the fixed PowerShell
// scripts through the real Windows gatherers and checks the invocation.
func TestWindowsGatherers(t *testing.T) {
	f := &fakeSystem{scripts: map[string]reply{
		PSAntivirus:   {stdout: "\xEF\xBB\xBF" + string(fixture(t, "win_av_client_defender.json")) + "\r\n"},
		PSFirewall:    {stdout: string(fixture(t, "win_fw_inactive_profile_off.json"))},
		PSBitLocker:   {stdout: string(fixture(t, "win_bitlocker_suspended.json"))},
		PSLocalAdmins: {stdout: string(fixture(t, "win_admins.json"))},
		PSLastPatch:   {stdout: "WARNING: noise\r\n" + string(fixture(t, "win_lastpatch.json"))},
	}}
	c := f.collector(&platform.Fake{})
	ctx := context.Background()

	av, err := c.Antivirus(ctx)
	if err != nil || len(av) != 1 || av[0].Source != SourceWSC || !av[0].Enabled {
		t.Errorf("antivirus: %+v %v", av, err)
	}
	if fw, err := c.Firewall(ctx); err != nil || !fw.Enabled {
		t.Errorf("firewall: %+v %v", fw, err)
	}
	if vols, err := c.DiskEncryption(ctx); err != nil || !reflect.DeepEqual(vols, []protocol.DiskEncryption{{Volume: "C:", Method: "bitlocker", Status: "unknown"}}) {
		t.Errorf("bitlocker: %+v %v", vols, err)
	}
	if admins, err := c.LocalAdmins(ctx); err != nil || len(admins) != 5 {
		t.Errorf("admins: %+v %v", admins, err)
	}
	if when, err := c.LastPatchDate(ctx); err != nil || when.Format("2006-01-02") != "2026-11-03" {
		t.Errorf("last patch: %v %v", when, err)
	}
	for _, call := range f.calls {
		if !strings.HasSuffix(call.Path, `\System32\WindowsPowerShell\v1.0\powershell.exe`) ||
			!reflect.DeepEqual(call.Args, []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"}) ||
			call.Stdin == nil || call.AsUser != nil {
			t.Errorf("invocation: %+v", call)
		}
	}

	// PowerShell fails to start: a plain error, the section stays null.
	f.scripts = map[string]reply{}
	if _, err := c.Firewall(ctx); err == nil {
		t.Error("missing output accepted")
	}
}
