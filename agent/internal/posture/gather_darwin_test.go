//go:build darwin

package posture

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func darwinFake(t *testing.T) *fakeSystem {
	t.Helper()
	return &fakeSystem{
		replies: map[string]reply{
			"/usr/sbin/spctl --status": {stdout: "assessments enabled\n"},
			"/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": {stdout: "Firewall is enabled. (State = 1)\n"},
			"/usr/bin/fdesetup status":                            {stdout: "FileVault is On.\n"},
			"/usr/bin/dscl . -read /Groups/admin GroupMembership": {stdout: "GroupMembership: root alice\n"},
			// sysadminctl answers on stderr.
			"/usr/sbin/sysadminctl -screenLock status":                           {stderr: "2026-11-11 10:00:00.000 sysadminctl[1:2] screenLock delay is 5 seconds\n"},
			"/usr/bin/defaults -currentHost read com.apple.screensaver idleTime": {stdout: "300\n"},
			"/usr/bin/pmset -g": {stdout: string(fixture(t, "pmset.txt"))},
			"/usr/bin/plutil -convert xml1 -o - -- /Library/Receipts/InstallHistory.plist": {stdout: string(fixture(t, "install_history.plist"))},
		},
		files: map[string]string{
			"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist": string(fixture(t, "xprotect_info.plist")),
			"/var/protected/xprotect/XProtect.bundle/Contents/Info.plist":                    strings.Replace(string(fixture(t, "xprotect_info.plist")), "5372", "5290", 1),
			"/Library/Preferences/com.apple.SoftwareUpdate.plist":                            string(fixture(t, "softwareupdate_prefs.plist")),
			"/usr/libexec/ApplicationFirewall/socketfilterfw":                                "",
			// A binary plist: converted through plutil.
			"/Library/Receipts/InstallHistory.plist": "bplist00...",
			"/Applications/Falcon.app":               "",
		},
		procs: []string{"launchd", "falcond"},
	}
}

func TestDarwinGatherers(t *testing.T) {
	f := darwinFake(t)
	plat := &platform.Fake{User: &platform.User{Name: "alice", UID: "501", GID: "20"}}
	c := f.collector(plat)
	p := c.Collect(context.Background())

	wantAV := []protocol.AntivirusProduct{
		// The higher of the two bundle versions; ConfigDataInstall is false in the fixture.
		{Name: "XProtect", Enabled: true, UpToDate: false, SignatureVersion: "5372", Source: "xprotect"},
		{Name: "Gatekeeper", Enabled: true, UpToDate: true, Source: "xprotect"},
		{Name: "CrowdStrike Falcon", Enabled: true, UpToDate: true, Source: "known_av"},
	}
	if !reflect.DeepEqual(p.Antivirus, wantAV) {
		t.Errorf("antivirus:\n got %+v\nwant %+v", p.Antivirus, wantAV)
	}
	if p.Firewall == nil || !p.Firewall.Enabled {
		t.Errorf("firewall: %+v", p.Firewall)
	}
	if !reflect.DeepEqual(p.DiskEncryption, []protocol.DiskEncryption{{Volume: "/", Method: "filevault", Status: "encrypted"}}) {
		t.Errorf("encryption: %+v", p.DiskEncryption)
	}
	if !reflect.DeepEqual(p.LocalAdmins, []string{"alice", "root"}) {
		t.Errorf("admins: %+v", p.LocalAdmins)
	}
	// Screen saver after 300 s (display sleep is 600 s), password 5 s later.
	if p.ScreenLock == nil || *p.ScreenLock != (protocol.ScreenLock{Enabled: true, TimeoutSeconds: 305}) {
		t.Errorf("screen lock: %+v", p.ScreenLock)
	}
	if p.LastPatchDate == nil || !p.LastPatchDate.Equal(time.Date(2026, 8, 27, 6, 41, 10, 0, time.UTC)) {
		t.Errorf("last patch: %v", p.LastPatchDate)
	}
	for _, s := range p.Unsupported {
		if s != SectionListeningPorts { // the socket table is real and may be unreadable
			t.Errorf("unexpected unsupported section %s", s)
		}
	}

	// The per-user commands ran as the console user; everything else as the agent.
	asUser := map[string]bool{}
	for _, call := range f.calls {
		if call.AsUser != nil {
			if call.AsUser.Name != "alice" {
				t.Errorf("ran as %q", call.AsUser.Name)
			}
			asUser[call.Path] = true
		}
	}
	if !reflect.DeepEqual(asUser, map[string]bool{"/usr/sbin/sysadminctl": true, "/usr/bin/defaults": true}) {
		t.Errorf("commands run as the user: %v", asUser)
	}
}

func TestDarwinGatherEdgeCases(t *testing.T) {
	ctx := context.Background()

	// Gatekeeper off (spctl exits 1), FileVault converting, firewall off, lock off.
	f := darwinFake(t)
	f.replies["/usr/sbin/spctl --status"] = reply{stdout: "assessments disabled\n", code: 1}
	f.replies["/usr/bin/fdesetup status"] = reply{stdout: "FileVault is On.\nEncryption in progress: Percent completed = 43\n"}
	f.replies["/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"] = reply{stdout: "Firewall is disabled. (State = 0)\n"}
	f.replies["/usr/sbin/sysadminctl -screenLock status"] = reply{stderr: "sysadminctl[1:2] screenLock is off\n"}
	c := f.collector(&platform.Fake{User: &platform.User{Name: "alice", UID: "501", GID: "20"}})
	av, err := c.Antivirus(ctx)
	if err != nil || len(av) < 2 || av[1].Name != "Gatekeeper" || av[1].Enabled {
		t.Errorf("gatekeeper off: %+v %v", av, err)
	}
	if vols, err := c.DiskEncryption(ctx); err != nil || vols[0].Status != "in_progress" {
		t.Errorf("in progress: %+v %v", vols, err)
	}
	if fw, err := c.Firewall(ctx); err != nil || fw.Enabled {
		t.Errorf("firewall off: %+v %v", fw, err)
	}
	if sl, err := c.ScreenLock(ctx); err != nil || sl.Enabled {
		t.Errorf("lock off: %+v %v", sl, err)
	}

	// Nobody logged in: the screen lock is unsupported, not guessed.
	c = darwinFake(t).collector(&platform.Fake{})
	if _, err := c.ScreenLock(ctx); !isUnsupported(err) {
		t.Errorf("no console user: %v", err)
	}

	// The screen saver idle time is not set (defaults exits 1): only the
	// display sleep timer counts. A managed preference would win.
	f = darwinFake(t)
	f.replies["/usr/bin/defaults -currentHost read com.apple.screensaver idleTime"] = reply{stderr: "The domain/default pair of (com.apple.screensaver, idleTime) does not exist\n", code: 1}
	c = f.collector(&platform.Fake{User: &platform.User{Name: "alice", UID: "501", GID: "20"}})
	if sl, err := c.ScreenLock(ctx); err != nil || *sl != (protocol.ScreenLock{Enabled: true, TimeoutSeconds: 605}) {
		t.Errorf("no idleTime: %+v %v", sl, err)
	}
	f.files["/Library/Managed Preferences/com.apple.screensaver.plist"] = `<plist version="1.0"><dict><key>idleTime</key><integer>120</integer></dict></plist>`
	if sl, err := c.ScreenLock(ctx); err != nil || *sl != (protocol.ScreenLock{Enabled: true, TimeoutSeconds: 125}) {
		t.Errorf("managed idleTime: %+v %v", sl, err)
	}

	// No XProtect bundle, no spctl answer, no third-party product: unsupported.
	f = darwinFake(t)
	f.files = map[string]string{}
	f.procs = nil
	delete(f.replies, "/usr/sbin/spctl --status")
	c = f.collector(&platform.Fake{})
	if _, err := c.Antivirus(ctx); !isUnsupported(err) {
		t.Errorf("nothing readable: %v", err)
	}
	if _, err := c.Firewall(ctx); !isUnsupported(err) {
		t.Errorf("socketfilterfw missing: %v", err)
	}
	if _, err := c.LastPatchDate(ctx); !isUnsupported(err) {
		t.Errorf("no install history: %v", err)
	}
}

// TestDarwinLive runs the real macOS collectors on this machine. Opt in with
// DRANZO_POSTURE_LIVE=1 (it runs read-only system tools such as fdesetup,
// spctl, dscl and sysadminctl as the current user).
func TestDarwinLive(t *testing.T) {
	if os.Getenv("DRANZO_POSTURE_LIVE") != "1" {
		t.Skip("set DRANZO_POSTURE_LIVE=1 to run the macOS collectors for real")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// The fake platform runs commands for real (as the current user) and
	// names the current user as the console user.
	me := &platform.User{Name: os.Getenv("USER"), UID: strconv.Itoa(os.Getuid()), GID: strconv.Itoa(os.Getgid())}
	c := New(&platform.Fake{User: me}, nil)
	p := c.Collect(ctx)

	raw, _ := json.MarshalIndent(p, "", "  ")
	// Account names are private: print the report without them.
	redacted := *p
	redacted.LocalAdmins = make([]string, len(p.LocalAdmins))
	for i := range redacted.LocalAdmins {
		redacted.LocalAdmins[i] = "<account>"
	}
	shown, _ := json.MarshalIndent(redacted, "", "  ")
	t.Logf("posture (%d bytes):\n%s", len(raw), shown)

	var xprotect, gatekeeper bool
	for _, a := range p.Antivirus {
		switch a.Name {
		case NameXProtect:
			xprotect = true
			if n, err := strconv.Atoi(a.SignatureVersion); err != nil || n < 1000 || !a.Enabled || a.Source != SourceXProtect {
				t.Errorf("XProtect entry: %+v", a)
			}
		case NameGatekeeper:
			gatekeeper = true
		}
	}
	if !xprotect || !gatekeeper {
		t.Errorf("XProtect found=%v Gatekeeper found=%v: %+v", xprotect, gatekeeper, p.Antivirus)
	}
	if p.Firewall == nil || !strings.HasPrefix(p.Firewall.Detail, "Application Firewall: ") {
		t.Errorf("firewall: %+v", p.Firewall)
	}
	if len(p.DiskEncryption) != 1 || p.DiskEncryption[0].Volume != "/" {
		t.Fatalf("disk encryption: %+v", p.DiskEncryption)
	}
	switch v := p.DiskEncryption[0]; v.Status {
	case StatusEncrypted, StatusInProgress:
		if v.Method != MethodFileVault {
			t.Errorf("method %q", v.Method)
		}
	case StatusDecrypted:
		if v.Method != MethodNone {
			t.Errorf("method %q", v.Method)
		}
	default:
		t.Errorf("status %q", v.Status)
	}
	if len(p.LocalAdmins) == 0 {
		t.Error("the admin group has no members")
	}
	foundRoot := false
	for _, a := range p.LocalAdmins {
		foundRoot = foundRoot || a == "root"
	}
	if !foundRoot {
		t.Error("root is not in the admin group")
	}
	if p.ScreenLock == nil {
		t.Errorf("screen lock not read (unsupported: %v)", p.Unsupported)
	} else if p.ScreenLock.Enabled != (p.ScreenLock.TimeoutSeconds > 0) {
		t.Errorf("screen lock: %+v", p.ScreenLock)
	}
	if p.LastPatchDate == nil || p.LastPatchDate.After(time.Now()) || p.LastPatchDate.Year() < 2015 {
		t.Errorf("last patch date: %v", p.LastPatchDate)
	}
	if p.ListeningPorts == nil {
		t.Errorf("listening ports not read (unsupported: %v)", p.Unsupported)
	}
	for _, lp := range p.ListeningPorts {
		if (lp.Protocol != "tcp" && lp.Protocol != "udp") || lp.Port < 1 || lp.Port > 65535 || lp.Address == "" || lp.Address == "*" {
			t.Errorf("port entry: %+v", lp)
		}
	}
	if len(p.Unsupported) != 0 {
		t.Errorf("unsupported sections on a logged-in Mac: %v", p.Unsupported)
	}
}
