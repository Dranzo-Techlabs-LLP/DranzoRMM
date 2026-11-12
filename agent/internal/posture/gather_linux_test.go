//go:build linux

package posture

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func linuxFake(t *testing.T) *fakeSystem {
	t.Helper()
	return &fakeSystem{
		replies: map[string]reply{
			"/usr/sbin/ufw status":                                              {stdout: string(fixture(t, "ufw_status_active.txt"))},
			"/usr/sbin/nft list ruleset":                                        {stdout: string(fixture(t, "nft_ufw.txt"))},
			"/usr/bin/lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS":                 {stdout: string(fixture(t, "lsblk_luks_root.json"))},
			"/usr/bin/gsettings get org.gnome.desktop.session idle-delay":       {stdout: "uint32 300\n"},
			"/usr/bin/gsettings get org.gnome.desktop.screensaver lock-enabled": {stdout: "true\n"},
			"/usr/bin/gsettings get org.gnome.desktop.screensaver lock-delay":   {stdout: "uint32 30\n"},
		},
		files: map[string]string{
			"/etc/passwd":               string(fixture(t, "linux_passwd.txt")),
			"/etc/group":                string(fixture(t, "linux_group.txt")),
			"/etc/ufw/ufw.conf":         string(fixture(t, "ufw.conf")),
			"/var/log/dpkg.log":         string(fixture(t, "dpkg.log")),
			"/var/lib/clamav":           "",
			"/var/lib/clamav/daily.cld": string(fixture(t, "clamav_daily_header.bin")),
			"/opt/sentinelone":          "",
		},
		tools: map[string]string{"ufw": "/usr/sbin/ufw", "nft": "/usr/sbin/nft", "lsblk": "/usr/bin/lsblk", "gsettings": "/usr/bin/gsettings", "clamd": "/usr/sbin/clamd"},
		procs: []string{"systemd", "clamd", "freshclam", "sshd"},
	}
}

func TestLinuxGatherers(t *testing.T) {
	f := linuxFake(t)
	plat := &platform.Fake{User: &platform.User{Name: "alice", UID: "1000", GID: "1000"}, Reboot: true}
	p := f.collector(plat).Collect(context.Background())

	wantAV := []protocol.AntivirusProduct{
		{Name: "ClamAV", Enabled: true, UpToDate: true, SignatureVersion: "27812", Source: "clamav"},
		{Name: "SentinelOne", Enabled: false, UpToDate: false, Source: "known_av"}, // installed, daemon not running
	}
	if !reflect.DeepEqual(p.Antivirus, wantAV) {
		t.Errorf("antivirus:\n got %+v\nwant %+v", p.Antivirus, wantAV)
	}
	if p.Firewall == nil || !p.Firewall.Enabled || !strings.Contains(p.Firewall.Detail, "ufw: active") {
		t.Errorf("firewall: %+v", p.Firewall)
	}
	wantEnc := []protocol.DiskEncryption{
		{Volume: "/", Method: "luks", Status: "encrypted"},
		{Volume: "/home", Method: "luks", Status: "encrypted"},
		{Volume: "/srv/data", Method: "none", Status: "decrypted"},
	}
	if !reflect.DeepEqual(p.DiskEncryption, wantEnc) {
		t.Errorf("encryption: %+v", p.DiskEncryption)
	}
	if !reflect.DeepEqual(p.LocalAdmins, []string{"alice", "bob", "carol", "erin", "root", "toor"}) {
		t.Errorf("admins: %+v", p.LocalAdmins)
	}
	if p.ScreenLock == nil || *p.ScreenLock != (protocol.ScreenLock{Enabled: true, TimeoutSeconds: 330}) {
		t.Errorf("screen lock: %+v", p.ScreenLock)
	}
	if p.LastPatchDate == nil || p.LastPatchDate.Format("2006-01-02") != "2026-11-09" {
		t.Errorf("last patch: %v", p.LastPatchDate)
	}
	if !p.PendingReboot {
		t.Error("pending reboot lost")
	}
	for _, s := range p.Unsupported {
		if s != SectionListeningPorts {
			t.Errorf("unexpected unsupported section %s", s)
		}
	}
	// gsettings ran as the console user, with a locale-independent environment.
	ranGsettings := 0
	for _, call := range f.calls {
		if call.Path == "/usr/bin/gsettings" {
			ranGsettings++
			if call.AsUser == nil || call.AsUser.Name != "alice" {
				t.Errorf("gsettings not run as the console user: %+v", call.AsUser)
			}
		}
		if !reflect.DeepEqual(call.Env, []string{"LC_ALL=C", "LANG=C"}) {
			t.Errorf("%s: env %v", call.Path, call.Env)
		}
	}
	if ranGsettings != 3 {
		t.Errorf("gsettings calls: %d", ranGsettings)
	}
}

func TestLinuxGatherEdgeCases(t *testing.T) {
	ctx := context.Background()

	// A minimal server: no AV, firewalld stopped, old lsblk, no desktop, RPM.
	f := &fakeSystem{
		replies: map[string]reply{
			"/usr/bin/firewall-cmd --state": {stderr: "not running\n", code: 252},
			"/usr/sbin/nft list ruleset":    {stdout: ""},
			// util-linux before 2.37 does not know MOUNTPOINTS.
			"/usr/bin/lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS": {stderr: "lsblk: unknown column: MOUNTPOINTS\n", code: 1},
			"/usr/bin/lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINT":  {stdout: string(fixture(t, "lsblk_plain_old.json"))},
			`/usr/bin/rpm -qa --queryformat %{INSTALLTIME}\n`:   {stdout: "1793000000\n1794043560\n"},
		},
		files: map[string]string{
			"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
			"/etc/group":  "root:x:0:\nwheel:x:10:\n",
		},
		tools: map[string]string{"firewall-cmd": "/usr/bin/firewall-cmd", "nft": "/usr/sbin/nft", "lsblk": "/usr/bin/lsblk", "rpm": "/usr/bin/rpm"},
		procs: []string{"systemd", "sshd"},
	}
	c := f.collector(&platform.Fake{})
	if av, err := c.Antivirus(ctx); err != nil || av == nil || len(av) != 0 {
		t.Errorf("no AV: %+v %v", av, err)
	}
	if fw, err := c.Firewall(ctx); err != nil || fw.Enabled || !strings.Contains(fw.Detail, "firewalld: not running") {
		t.Errorf("firewalld stopped: %+v %v", fw, err)
	}
	if vols, err := c.DiskEncryption(ctx); err != nil || !reflect.DeepEqual(vols, []protocol.DiskEncryption{{Volume: "/", Method: "none", Status: "decrypted"}}) {
		t.Errorf("old lsblk: %+v %v", vols, err)
	}
	if admins, err := c.LocalAdmins(ctx); err != nil || !reflect.DeepEqual(admins, []string{"root"}) {
		t.Errorf("admins: %+v %v", admins, err)
	}
	if _, err := c.ScreenLock(ctx); !isUnsupported(err) {
		t.Errorf("no desktop: %v", err)
	}
	if when, err := c.LastPatchDate(ctx); err != nil || !when.Equal(time.Unix(1794043560, 0)) {
		t.Errorf("rpm: %v %v", when, err)
	}

	// firewalld running.
	f.replies["/usr/bin/firewall-cmd --state"] = reply{stdout: "running\n"}
	f.replies["/usr/sbin/nft list ruleset"] = reply{stdout: string(fixture(t, "nft_firewalld.txt"))}
	if fw, err := c.Firewall(ctx); err != nil || !fw.Enabled || !strings.Contains(fw.Detail, "firewalld: running") {
		t.Errorf("firewalld running: %+v %v", fw, err)
	}

	// No firewall tool at all: a definite "off".
	f.tools = map[string]string{}
	if fw, err := c.Firewall(ctx); err != nil || fw.Enabled || !strings.Contains(fw.Detail, "not installed") {
		t.Errorf("no firewall: %+v %v", fw, err)
	}
	if _, err := c.DiskEncryption(ctx); !isUnsupported(err) {
		t.Errorf("no lsblk: %v", err)
	}
	if _, err := c.LastPatchDate(ctx); !isUnsupported(err) {
		t.Errorf("no package log: %v", err)
	}

	// GNOME installed but nobody at the console.
	f.tools = map[string]string{"gsettings": "/usr/bin/gsettings"}
	if _, err := c.ScreenLock(ctx); !isUnsupported(err) {
		t.Errorf("no console user: %v", err)
	}

	// A container: lsblk sees the host's disks, "/" is an overlay.
	f.tools = map[string]string{"lsblk": "/usr/bin/lsblk"}
	f.replies["/usr/bin/lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS"] = reply{stdout: string(fixture(t, "lsblk_container.json"))}
	if _, err := c.DiskEncryption(ctx); !isUnsupported(err) {
		t.Errorf("container: %v", err)
	}
}

// TestLinuxLive runs the real Linux collectors (as root, in a throwaway
// container). Opt in with DRANZO_POSTURE_LIVE=1. The expectations come from
// the environment so that one test binary serves several scenarios:
//
//	DRANZO_EXPECT_ADMINS    comma-separated account names that must be listed
//	DRANZO_EXPECT_FIREWALL  "on", "off" or "unsupported"
//	DRANZO_EXPECT_AV        a product name that must be listed ("" = none)
//	DRANZO_EXPECT_PATCHDATE "1" a date must be reported, "0" it must be unsupported
//	DRANZO_EXPECT_CONTAINER "1" disk encryption must be unsupported (overlay root)
func TestLinuxLive(t *testing.T) {
	if os.Getenv("DRANZO_POSTURE_LIVE") != "1" {
		t.Skip("set DRANZO_POSTURE_LIVE=1 to run the Linux collectors for real")
	}
	// A real listener the report must contain.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := New(platform.New(), nil)
	p := c.Collect(ctx)
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("posture:\n%s", raw)

	// Well-formed: every section is filled or listed, never both.
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

	// Local administrators.
	admins := map[string]bool{}
	for _, a := range p.LocalAdmins {
		admins[a] = true
	}
	if !admins["root"] {
		t.Errorf("root missing: %v", p.LocalAdmins)
	}
	for _, want := range strings.Split(os.Getenv("DRANZO_EXPECT_ADMINS"), ",") {
		if want != "" && !admins[want] {
			t.Errorf("administrator %q missing: %v", want, p.LocalAdmins)
		}
	}

	// The listener started above, with this test binary as the process.
	found := false
	for _, lp := range p.ListeningPorts {
		if lp.Port == port && lp.Protocol == "tcp" && lp.Address == "127.0.0.1" {
			found = true
			if lp.Process == "" {
				t.Errorf("listener without a process name: %+v", lp)
			}
		}
	}
	if !found {
		t.Errorf("listener on 127.0.0.1:%d not reported: %+v", port, p.ListeningPorts)
	}

	switch os.Getenv("DRANZO_EXPECT_FIREWALL") {
	case "on":
		if p.Firewall == nil || !p.Firewall.Enabled {
			t.Errorf("firewall: %+v (unsupported %v)", p.Firewall, p.Unsupported)
		}
	case "off":
		if p.Firewall == nil || p.Firewall.Enabled {
			t.Errorf("firewall: %+v (unsupported %v)", p.Firewall, p.Unsupported)
		}
	case "unsupported":
		if !missing[SectionFirewall] {
			t.Errorf("firewall: %+v", p.Firewall)
		}
	}

	// A container's root file system is an overlay: the encryption state
	// must be reported as unknown, never as "decrypted".
	if os.Getenv("DRANZO_EXPECT_CONTAINER") == "1" && !missing[SectionDiskEncryption] {
		t.Errorf("disk encryption in a container: %+v", p.DiskEncryption)
	}
	if want := os.Getenv("DRANZO_EXPECT_AV"); want != "" {
		ok := false
		for _, a := range p.Antivirus {
			ok = ok || a.Name == want
		}
		if !ok {
			t.Errorf("antivirus %q missing: %+v", want, p.Antivirus)
		}
	} else if len(p.Antivirus) != 0 {
		t.Errorf("antivirus on a bare container: %+v", p.Antivirus)
	}
	// Stripped container images ship without a dpkg log: then the date is
	// unsupported rather than invented (DRANZO_EXPECT_PATCHDATE=0).
	switch os.Getenv("DRANZO_EXPECT_PATCHDATE") {
	case "1":
		if p.LastPatchDate == nil || p.LastPatchDate.After(time.Now().Add(time.Hour)) || p.LastPatchDate.Year() < 2015 {
			t.Errorf("last patch date: %v (unsupported %v)", p.LastPatchDate, p.Unsupported)
		}
	case "0":
		if !missing[SectionLastPatchDate] {
			t.Errorf("last patch date without a package log: %v", p.LastPatchDate)
		}
	}
	if !missing[SectionScreenLock] {
		t.Errorf("screen lock on a headless container: %+v", p.ScreenLock)
	}
}
