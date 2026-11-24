package posture

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ---- firewall ----

func TestParseWindowsFirewall(t *testing.T) {
	cases := []struct {
		file    string
		enabled bool
		detail  []string
	}{
		{"win_fw_all_on.json", true, []string{"Domain: on", "Private: on", "Public: on", "active: Private"}},
		// Domain is off but not in use: the profiles in use are both on.
		{"win_fw_inactive_profile_off.json", true, []string{"Domain: off", "active: Public, Private"}},
		// The one connected network is the domain network and its profile is off.
		{"win_fw_active_profile_off.json", false, []string{"Domain: off", "active: Domain"}},
		// No connected network: every profile must be on.
		{"win_fw_no_network.json", false, []string{"Public: off", "no connected network"}},
		// Windows Firewall off, a registered third-party firewall is on.
		{"win_fw_third_party.json", true, []string{"Private: off", "third-party: ESET Firewall (on)"}},
	}
	for _, c := range cases {
		fw, err := ParseWindowsFirewall(fixture(t, c.file))
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if fw.Enabled != c.enabled {
			t.Errorf("%s: enabled=%v (%s)", c.file, fw.Enabled, fw.Detail)
		}
		for _, d := range c.detail {
			if !strings.Contains(fw.Detail, d) {
				t.Errorf("%s: detail %q lacks %q", c.file, fw.Detail, d)
			}
		}
	}
	if _, err := ParseWindowsFirewall(fixture(t, "win_fw_unavailable.json")); !isUnsupported(err) {
		t.Errorf("unavailable: %v", err)
	}
}

func TestParseSocketFilterFW(t *testing.T) {
	cases := map[string]bool{
		"Firewall is enabled. (State = 1)\n":               true,
		"Firewall is disabled. (State = 0)\n":              false,
		"Firewall is set to block all. (State = 2) \n":     true,
		"Firewall is enabled.":                             true,
		"Firewall is disabled.":                            false,
		"The firewall is off":                              false,
		"Firewall is blocking all non-essential (State=2)": true,
	}
	for in, want := range cases {
		fw, err := ParseSocketFilterFW(in)
		if err != nil || fw.Enabled != want || fw.Detail == "" {
			t.Errorf("%q: %+v %v", in, fw, err)
		}
	}
	for _, bad := range []string{"", "usage: socketfilterfw [-c] ...", "State = 7"} {
		if _, err := ParseSocketFilterFW(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLinuxFirewallParsers(t *testing.T) {
	if a, ok := ParseUFWStatus(string(fixture(t, "ufw_status_active.txt"))); !ok || !a {
		t.Error("ufw active")
	}
	if a, ok := ParseUFWStatus("Status: inactive\n"); !ok || a {
		t.Error("ufw inactive")
	}
	if _, ok := ParseUFWStatus("ERROR: You need to be root to run this script\n"); ok {
		t.Error("ufw error accepted")
	}
	if e, ok := ParseUFWConf(string(fixture(t, "ufw.conf"))); !ok || !e {
		t.Error("ufw.conf yes")
	}
	if e, ok := ParseUFWConf("# ENABLED=yes\nENABLED=no\n"); !ok || e {
		t.Error("ufw.conf no")
	}
	if _, ok := ParseUFWConf("LOGLEVEL=low\n"); ok {
		t.Error("ufw.conf without ENABLED accepted")
	}

	if r, ok := ParseFirewalldState(Probe{Output: "running\n"}); !ok || !r {
		t.Error("firewalld running")
	}
	if r, ok := ParseFirewalldState(Probe{Output: "not running\n", ExitCode: 252}); !ok || r {
		t.Error("firewalld not running")
	}
	if _, ok := ParseFirewalldState(Probe{Output: "Traceback (most recent call last)", ExitCode: 1}); ok {
		t.Error("firewalld crash accepted")
	}

	nft := map[string]bool{
		"nft_ufw.txt":         true,  // policy drop on the input hook
		"nft_firewalld.txt":   true,  // policy accept, but drop / reject rules
		"nft_docker_only.txt": false, // NAT and forward chains, accept-only input
	}
	for file, want := range nft {
		if got := ParseNftRuleset(string(fixture(t, file))); got != want {
			t.Errorf("%s: %v", file, got)
		}
	}
	if ParseNftRuleset("") {
		t.Error("empty rule set filters")
	}
	if !ParseIptablesInput(string(fixture(t, "iptables_input_drop.txt"))) {
		t.Error("iptables reject rule")
	}
	if !ParseIptablesInput("-P INPUT DROP\n") || ParseIptablesInput("-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n") {
		t.Error("iptables policy")
	}
}

func TestLinuxFirewall(t *testing.T) {
	ufwActive := &Probe{Output: string(fixture(t, "ufw_status_active.txt"))}
	ufwInactive := &Probe{Output: "Status: inactive\n"}
	nftUFW := &Probe{Output: string(fixture(t, "nft_ufw.txt"))}
	nftEmpty := &Probe{Output: ""}
	nftDenied := &Probe{Output: "Operation not permitted (you must be root)", ExitCode: 1}

	cases := []struct {
		name        string
		probes      LinuxFirewallProbes
		enabled     bool
		unsupported bool
		detail      string
	}{
		{"ufw active", LinuxFirewallProbes{UFW: ufwActive, Nft: nftUFW}, true, false, "ufw: active"},
		{"ufw inactive, nothing else", LinuxFirewallProbes{UFW: ufwInactive, Nft: nftEmpty}, false, false, "ufw: inactive"},
		{"firewalld running", LinuxFirewallProbes{Firewalld: &Probe{Output: "running\n"}, Nft: &Probe{Output: string(fixture(t, "nft_firewalld.txt"))}}, true, false, "firewalld: running"},
		{"firewalld stopped", LinuxFirewallProbes{Firewalld: &Probe{Output: "not running\n", ExitCode: 252}, Nft: nftEmpty}, false, false, "firewalld: not running"},
		{"plain nftables", LinuxFirewallProbes{Nft: nftUFW}, true, false, "nftables: input filtering rules present"},
		{"docker rules only", LinuxFirewallProbes{Nft: &Probe{Output: string(fixture(t, "nft_docker_only.txt"))}}, false, false, "nftables: no input filtering rules"},
		{"legacy iptables", LinuxFirewallProbes{Iptables: &Probe{Output: string(fixture(t, "iptables_input_drop.txt"))}}, true, false, "iptables: input filtering rules present"},
		{"nothing installed", LinuxFirewallProbes{}, false, false, "ufw: not installed; firewalld: not installed; nftables / iptables: not installed"},
		// ufw could not be asked, its configuration file says enabled.
		{"ufw.conf fallback", LinuxFirewallProbes{UFW: &Probe{Output: "ERROR: problem running", ExitCode: 1}, UFWConf: "ENABLED=yes\n", Nft: nftDenied}, true, false, "ufw: active (ufw.conf)"},
		// Nothing says "on" and nft cannot be read: unknown, not "off".
		{"nft unreadable", LinuxFirewallProbes{UFW: ufwInactive, Nft: nftDenied}, false, true, ""},
		{"ufw unreadable", LinuxFirewallProbes{UFW: &Probe{Failed: true}, Nft: nftEmpty}, false, true, ""},
		// One tool unreadable but another positively on: enabled.
		{"nft unreadable, ufw active", LinuxFirewallProbes{UFW: ufwActive, Nft: nftDenied}, true, false, "nftables: not readable"},
	}
	for _, c := range cases {
		fw, err := LinuxFirewall(c.probes)
		if c.unsupported {
			if !isUnsupported(err) {
				t.Errorf("%s: want unsupported, got %+v %v", c.name, fw, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if fw.Enabled != c.enabled || !strings.Contains(fw.Detail, c.detail) {
			t.Errorf("%s: enabled=%v detail=%q", c.name, fw.Enabled, fw.Detail)
		}
	}
}

// ---- disk encryption ----

func TestParseBitLocker(t *testing.T) {
	cases := []struct {
		file string
		want []protocol.DiskEncryption
	}{
		// The removable E: drive is left out; output is sorted.
		{"win_bitlocker.json", []protocol.DiskEncryption{
			{Volume: "C:", Method: "bitlocker", Status: "encrypted"},
			{Volume: "D:", Method: "none", Status: "decrypted"},
		}},
		// Suspended (encrypted, protection off) is never "encrypted".
		{"win_bitlocker_suspended.json", []protocol.DiskEncryption{
			{Volume: "C:", Method: "bitlocker", Status: "unknown"},
		}},
		{"win_bitlocker_in_progress.json", []protocol.DiskEncryption{
			{Volume: "C:", Method: "bitlocker", Status: "in_progress"},
			{Volume: "F:", Method: "bitlocker", Status: "in_progress"},
		}},
	}
	for _, c := range cases {
		got, err := ParseBitLocker(fixture(t, c.file))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v %v", c.file, got, err)
		}
	}
	if _, err := ParseBitLocker(fixture(t, "win_bitlocker_unavailable.json")); !isUnsupported(err) {
		t.Errorf("unavailable: %v", err)
	}
	// No BitLocker cmdlets, but no volumes either (an empty list) is a valid answer.
	if got, err := ParseBitLocker([]byte(`{"volumes":[],"error":"","manageBde":""}`)); err != nil || got == nil || len(got) != 0 {
		t.Errorf("empty: %+v %v", got, err)
	}
}

func TestParseManageBde(t *testing.T) {
	want := []protocol.DiskEncryption{
		{Volume: "C:", Method: "bitlocker", Status: "encrypted"},
		{Volume: "D:", Method: "none", Status: "decrypted"},
		{Volume: "E:", Method: "bitlocker", Status: "in_progress"},
		{Volume: "F:", Method: "bitlocker", Status: "unknown"}, // suspended
	}
	text := string(fixture(t, "manage_bde.txt"))
	got, err := ParseManageBde(text)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v %v", got, err)
	}
	// The same text through the fallback field of the script output, CRLF.
	payload := `{"volumes":null,"error":"cmdlet missing","manageBde":` + jsonString(strings.ReplaceAll(text, "\n", "\r\n")) + `}`
	got, err = ParseBitLocker([]byte(payload))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback: %+v %v", got, err)
	}
	// A localised manage-bde is not understood: unsupported, not a guess.
	german := `{"volumes":null,"error":"","manageBde":"Volume C: [Windows]\n    Konvertierungsstatus: Vollständig verschlüsselt\n"}`
	if _, err := ParseBitLocker([]byte(german)); !isUnsupported(err) {
		t.Errorf("localised: %v", err)
	}
}

func jsonString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func TestParseFdesetupStatus(t *testing.T) {
	cases := map[string]protocol.DiskEncryption{
		"FileVault is On.\n":  {Volume: "/", Method: "filevault", Status: "encrypted"},
		"FileVault is Off.\n": {Volume: "/", Method: "none", Status: "decrypted"},
		"FileVault is On.\nEncryption in progress: Percent completed = 43\n":                    {Volume: "/", Method: "filevault", Status: "in_progress"},
		"FileVault is Off.\nDecryption in progress: Percent completed = 8\n":                    {Volume: "/", Method: "filevault", Status: "in_progress"},
		"FileVault is On, but needs to be restarted to finish.\n":                               {Volume: "/", Method: "filevault", Status: "in_progress"},
		"FileVault is Off.\nDeferred enablement appears to be active for user 'alice'.\n":       {Volume: "/", Method: "none", Status: "decrypted"},
		"FileVault is On.\nFileVault master keychain appears to be installed.\n":                {Volume: "/", Method: "filevault", Status: "encrypted"},
		"FileVault is Off.\nFileVault decryption was interrupted; decryption in progress: 2%\n": {Volume: "/", Method: "filevault", Status: "in_progress"},
	}
	for in, want := range cases {
		got, err := ParseFdesetupStatus(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "Error: Unable to get FileVault status.", "fdesetup: device is locked"} {
		if _, err := ParseFdesetupStatus(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseLsblk(t *testing.T) {
	cases := []struct {
		file string
		want []protocol.DiskEncryption
	}{
		// LUKS under LVM: / and /home encrypted, the second plain disk is
		// not; /boot, the EFI partition, swap and snap images are left out.
		{"lsblk_luks_root.json", []protocol.DiskEncryption{
			{Volume: "/", Method: "luks", Status: "encrypted"},
			{Volume: "/home", Method: "luks", Status: "encrypted"},
			{Volume: "/srv/data", Method: "none", Status: "decrypted"},
		}},
		// util-linux before 2.37: "mountpoint" instead of "mountpoints".
		{"lsblk_plain_old.json", []protocol.DiskEncryption{
			{Volume: "/", Method: "none", Status: "decrypted"},
		}},
		// One btrfs file system mounted twice on a LUKS device.
		{"lsblk_btrfs_luks.json", []protocol.DiskEncryption{
			{Volume: "/", Method: "luks", Status: "encrypted"},
			{Volume: "/home", Method: "luks", Status: "encrypted"},
		}},
		// A mirror with only one encrypted leg is not encrypted.
		{"lsblk_raid_mixed.json", []protocol.DiskEncryption{
			{Volume: "/", Method: "none", Status: "decrypted"},
		}},
	}
	for _, c := range cases {
		got, err := ParseLsblk(fixture(t, c.file))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v %v", c.file, got, err)
		}
	}
	// In a container "/" is not on a listed block device: unknown.
	if _, err := ParseLsblk(fixture(t, "lsblk_container.json")); !isUnsupported(err) {
		t.Errorf("container: %v", err)
	}
	if _, err := ParseLsblk([]byte("lsblk: unknown column")); err == nil || isUnsupported(err) {
		t.Errorf("garbage: %v", err)
	}
}

// ---- local administrators ----

func TestParseWindowsAdmins(t *testing.T) {
	got, err := ParseWindowsAdmins(fixture(t, "win_admins.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := []AdminAccount{
		{Name: "Administrator", SID: "S-1-5-21-1004336348-1177238915-682003330-500", Class: "User", Builtin: true},
		{Name: `AzureAD\BobSmith`, SID: "S-1-12-1-2331285811-1146340712-3415128470-1634523331", Class: "User"},
		{Name: `CONTOSO\Domain Admins`, SID: "S-1-5-21-3623811015-3361044348-30300820-512", Class: "Group"},
		// An orphaned SID has no name: the SID stands in for it.
		{Name: "S-1-5-21-3623811015-3361044348-30300820-1190", SID: "S-1-5-21-3623811015-3361044348-30300820-1190", Class: "User"},
		{Name: "jane", SID: "S-1-5-21-1004336348-1177238915-682003330-1001", Class: "User"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
	if names := AdminNames(got); !reflect.DeepEqual(names, []string{"Administrator", `AzureAD\BobSmith`, `CONTOSO\Domain Admins`, "S-1-5-21-3623811015-3361044348-30300820-1190", "jane"}) {
		t.Errorf("names: %q", names)
	}

	// Fallback: Get-LocalGroupMember failed, `net localgroup` text is used.
	payload := `{"computer":"ACME-LT-042","members":null,"error":"Failed to compare two elements in the array.","netOutput":` +
		jsonString(strings.ReplaceAll(string(fixture(t, "net_localgroup.txt")), "\n", "\r\n")) + `,"builtinAdmin":"Administrator"}`
	got, err = ParseWindowsAdmins([]byte(payload))
	want = []AdminAccount{
		{Name: "Administrator", Builtin: true},
		{Name: `CONTOSO\Domain Admins`},
		{Name: "jane"},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("fallback:\n got %+v %v\nwant %+v", got, err, want)
	}
	// A German Windows: the labels differ, the layout does not.
	if m := ParseNetLocalGroup(string(fixture(t, "net_localgroup_de.txt"))); !reflect.DeepEqual(m, []string{"Administrator", "Anna Müller"}) {
		t.Errorf("german: %q", m)
	}
	if m := ParseNetLocalGroup("System error 5 has occurred.\n\nAccess is denied.\n"); m != nil {
		t.Errorf("error text: %q", m)
	}
	if _, err := ParseWindowsAdmins([]byte(`{"computer":"X","members":null,"error":"boom","netOutput":"","builtinAdmin":""}`)); !isUnsupported(err) {
		t.Errorf("unavailable: %v", err)
	}
	// An empty group is an answer, not an error.
	if got, err := ParseWindowsAdmins([]byte(`{"computer":"X","members":[],"error":"","netOutput":"","builtinAdmin":""}`)); err != nil || len(got) != 0 {
		t.Errorf("empty: %+v %v", got, err)
	}
	if StripLocalPrefix(`.\jane`, "PC") != "jane" || StripLocalPrefix(`pc\jane`, "PC") != "jane" || StripLocalPrefix(`CORP\jane`, "PC") != `CORP\jane` || StripLocalPrefix("jane", "PC") != "jane" {
		t.Error("StripLocalPrefix")
	}
}

func TestParseDsclGroupMembership(t *testing.T) {
	got, err := ParseDsclGroupMembership("GroupMembership: root alice _mbsetupuser alice\n")
	want := []AdminAccount{
		{Name: "_mbsetupuser", Groups: []string{"admin"}},
		{Name: "alice", Groups: []string{"admin"}},
		{Name: "root", Builtin: true, Groups: []string{"admin"}},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%+v %v", got, err)
	}
	// dscl wraps long values onto the next line.
	got, err = ParseDsclGroupMembership("GroupMembership:\n root alice\n")
	if err != nil || len(got) != 2 {
		t.Errorf("wrapped: %+v %v", got, err)
	}
	if got, err := ParseDsclGroupMembership("No such key: GroupMembership\n"); err != nil || len(got) != 0 {
		t.Errorf("no key: %+v %v", got, err)
	}
	if _, err := ParseDsclGroupMembership("<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n"); err == nil {
		t.Error("error text accepted")
	}
}

func TestParseLinuxAdmins(t *testing.T) {
	got := ParseLinuxAdmins(string(fixture(t, "linux_passwd.txt")), string(fixture(t, "linux_group.txt")))
	want := []AdminAccount{
		{Name: "alice", Groups: []string{"sudo"}},
		{Name: "bob", Groups: []string{"sudo", "wheel"}},
		{Name: "carol", Primary: true}, // primary group is sudo
		{Name: "erin", Groups: []string{"wheel"}},
		{Name: "root", Builtin: true, Primary: true},
		{Name: "toor", Primary: true}, // a second uid 0 account is not "built in"
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
	// A minimal container: only root.
	got = ParseLinuxAdmins("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/:/usr/sbin/nologin\n", "root:x:0:\nsudo:x:27:\n")
	if !reflect.DeepEqual(got, []AdminAccount{{Name: "root", Builtin: true, Primary: true}}) {
		t.Errorf("container: %+v", got)
	}
	if got := ParseLinuxAdmins("", ""); len(got) != 0 {
		t.Errorf("empty: %+v", got)
	}
}

// ---- screen lock ----

func TestWindowsScreenLock(t *testing.T) {
	cases := []struct {
		name       string
		inactivity uint64
		saver      *ScreenSaver
		ok         bool
		want       protocol.ScreenLock
	}{
		{"machine limit only", 900, nil, true, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 900}},
		{"secure screen saver", 0, &ScreenSaver{Active: true, Secure: true, TimeoutSeconds: 600}, true, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 600}},
		{"the shorter one wins", 900, &ScreenSaver{Active: true, Secure: true, TimeoutSeconds: 300}, true, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 300}},
		{"machine limit shorter", 120, &ScreenSaver{Active: true, Secure: true, TimeoutSeconds: 300}, true, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 120}},
		{"screen saver without password", 0, &ScreenSaver{Active: true, Secure: false, TimeoutSeconds: 300}, true, protocol.ScreenLock{}},
		{"screen saver off", 0, &ScreenSaver{Active: false, Secure: true, TimeoutSeconds: 300}, true, protocol.ScreenLock{}},
		{"insecure saver, machine limit set", 600, &ScreenSaver{Active: true, TimeoutSeconds: 60}, true, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 600}},
		{"nothing known", 0, nil, false, protocol.ScreenLock{}},
	}
	for _, c := range cases {
		got, ok := WindowsScreenLock(c.inactivity, c.saver)
		if ok != c.ok || (ok && *got != c.want) {
			t.Errorf("%s: %+v %v", c.name, got, ok)
		}
	}
	if !ParseRegFlag("1") || ParseRegFlag("0") || ParseRegFlag("") || ParseRegSeconds(" 600 ") != 600 || ParseRegSeconds("-5") != 0 || ParseRegSeconds("x") != 0 {
		t.Error("registry string helpers")
	}
}

func TestMacScreenLock(t *testing.T) {
	type parsed struct {
		delay   int
		off, ok bool
	}
	outputs := map[string]parsed{
		"2026-11-11 22:44:38.493 sysadminctl[29354:39184001] screenLock delay is immediate\n":   {0, false, true},
		"2026-11-11 22:44:38.493 sysadminctl[29354:39184001] screenLock delay is 300 seconds\n": {300, false, true},
		"2026-11-11 22:44:38.493 sysadminctl[29354:39184001] screenLock delay is 1 second\n":    {1, false, true},
		"2026-11-11 22:44:38.493 sysadminctl[29354:39184001] screenLock is off\n":               {0, true, true},
		"sysadminctl: unknown option -screenLock\n":                                             {0, false, false},
	}
	for in, want := range outputs {
		delay, off, ok := ParseSysadminctlScreenLock(in)
		if (parsed{delay, off, ok}) != want {
			t.Errorf("%q: %d %v %v", in, delay, off, ok)
		}
	}
	if m, ok := ParsePmsetDisplaySleep(string(fixture(t, "pmset.txt"))); !ok || m != 10 {
		t.Errorf("pmset: %d %v", m, ok)
	}
	if _, ok := ParsePmsetDisplaySleep("System-wide power settings:\n sleep 1\n"); ok {
		t.Error("pmset without displaysleep accepted")
	}

	cases := []struct {
		name                       string
		off                        bool
		delay, saver, displaySleep int
		want                       protocol.ScreenLock
	}{
		{"display sleep only", false, 0, 0, 10, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 600}},
		{"screen saver first", false, 5, 300, 10, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 305}},
		{"display sleep first", false, 60, 1200, 2, protocol.ScreenLock{Enabled: true, TimeoutSeconds: 180}},
		{"password not required", true, 0, 300, 10, protocol.ScreenLock{}},
		{"never idle", false, 0, 0, 0, protocol.ScreenLock{}},
	}
	for _, c := range cases {
		if got := MacScreenLock(c.off, c.delay, c.saver, c.displaySleep); *got != c.want {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

func TestGnomeScreenLock(t *testing.T) {
	if n, ok := ParseGsettingsUint("uint32 300\n"); !ok || n != 300 {
		t.Error("uint32")
	}
	if n, ok := ParseGsettingsUint("0\n"); !ok || n != 0 {
		t.Error("plain number")
	}
	if _, ok := ParseGsettingsUint("No such schema"); ok {
		t.Error("error text accepted")
	}
	if _, ok := ParseGsettingsUint(""); ok {
		t.Error("empty accepted")
	}
	if v, ok := ParseGsettingsBool("true\n"); !ok || !v {
		t.Error("bool true")
	}
	if v, ok := ParseGsettingsBool("false"); !ok || v {
		t.Error("bool false")
	}
	if _, ok := ParseGsettingsBool("yes"); ok {
		t.Error("bool garbage")
	}
	if got := GnomeScreenLock(300, true, 30); *got != (protocol.ScreenLock{Enabled: true, TimeoutSeconds: 330}) {
		t.Errorf("%+v", got)
	}
	if got := GnomeScreenLock(300, false, 0); got.Enabled {
		t.Errorf("lock disabled: %+v", got)
	}
	if got := GnomeScreenLock(0, true, 0); got.Enabled {
		t.Errorf("never idle: %+v", got)
	}
}

// ---- last patch date ----

func TestLastPatchParsers(t *testing.T) {
	// Windows: the newer of hotfix date and update history.
	got, err := ParseWindowsLastPatch(fixture(t, "win_lastpatch.json"))
	if err != nil || !got.Equal(time.Date(2026, 11, 3, 9, 41, 27, 0, time.UTC)) {
		t.Errorf("windows: %v %v", got, err)
	}
	if got, err := ParseWindowsLastPatch([]byte(`{"hotfix":"","wua":"","error":""}`)); err != nil || !got.IsZero() {
		t.Errorf("windows empty: %v %v", got, err)
	}
	if _, err := ParseWindowsLastPatch([]byte(`{"hotfix":"","wua":"","error":"Access is denied; 0x80070005"}`)); !isUnsupported(err) {
		t.Errorf("windows error: %v", err)
	}

	// macOS: the newest softwareupdated install that is not security data
	// (the later XProtect push, the App Store and a manual installer do not count).
	got, err = ParseInstallHistory(fixture(t, "install_history.plist"))
	if err != nil || !got.Equal(time.Date(2026, 8, 27, 6, 41, 10, 0, time.UTC)) {
		t.Errorf("macOS: %v %v", got, err)
	}
	if got, err := ParseInstallHistory([]byte(`<plist version="1.0"><array/></plist>`)); err != nil || !got.IsZero() {
		t.Errorf("macOS empty: %v %v", got, err)
	}
	if _, err := ParseInstallHistory([]byte(`<plist version="1.0"><dict/></plist>`)); err == nil {
		t.Error("macOS: dict root accepted")
	}

	// Debian: the removal on the 10th is not a patch.
	loc := time.FixedZone("CET", 3600)
	when, ok := ParseDpkgLog(string(fixture(t, "dpkg.log")), loc)
	if !ok || !when.Equal(time.Date(2026, 11, 9, 6, 31, 48, 0, loc)) {
		t.Errorf("dpkg: %v %v", when, ok)
	}
	if _, ok := ParseDpkgLog("2026-11-10 07:00:00 startup packages remove\ngarbage\n", nil); ok {
		t.Error("dpkg: no install lines accepted")
	}

	// RPM: install times as Unix seconds.
	when, ok = ParseRpmInstallTimes("1793000000\n1794043560\n(none)\n\n1790000000\n")
	if !ok || !when.Equal(time.Unix(1794043560, 0)) {
		t.Errorf("rpm: %v %v", when, ok)
	}
	if _, ok := ParseRpmInstallTimes("error: rpmdb open failed\n"); ok {
		t.Error("rpm: error text accepted")
	}
}

// ---- property lists ----

func TestPlist(t *testing.T) {
	info := fixture(t, "xprotect_info.plist")
	if v := PlistString(info, "CFBundleShortVersionString"); v != "5372" {
		t.Errorf("version %q", v)
	}
	if v := PlistString(info, "Missing"); v != "" {
		t.Errorf("missing key %q", v)
	}
	prefs := fixture(t, "softwareupdate_prefs.plist")
	if v, ok := PlistBool(prefs, "ConfigDataInstall"); !ok || v {
		t.Errorf("ConfigDataInstall %v %v", v, ok)
	}
	if v, ok := PlistBool(prefs, "CriticalUpdateInstall"); !ok || !v {
		t.Errorf("integer as bool %v %v", v, ok)
	}
	if _, ok := PlistBool(prefs, "LastAttemptSystemVersion"); ok {
		t.Error("string accepted as bool")
	}
	if n, ok := PlistInt(prefs, "LastResultCode"); !ok || n != 2 {
		t.Errorf("int %d %v", n, ok)
	}
	m, err := PlistDict(prefs)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := m["LastBackgroundSuccessfulDate"].(time.Time); !ok || !d.Equal(time.Date(2026, 11, 10, 5, 12, 1, 0, time.UTC)) {
		t.Errorf("date %v", m["LastBackgroundSuccessfulDate"])
	}
	if f, ok := m["Ratio"].(float64); !ok || f != 0.5 {
		t.Errorf("real %v", m["Ratio"])
	}
	if !IsBinaryPlist([]byte("bplist00\xd1")) || IsBinaryPlist(info) {
		t.Error("IsBinaryPlist")
	}
	for _, bad := range []string{"", "bplist00", "<plist><dict><key>a</key>", "<plist><dict><key>a</key><date>yesterday</date></dict></plist>",
		"<plist><wat/></plist>", "<plist>" + strings.Repeat("<array>", 40) + strings.Repeat("</array>", 40) + "</plist>"} {
		if _, err := ParsePlist([]byte(bad)); err == nil {
			t.Errorf("%.40q accepted", bad)
		}
	}
}

// ---- listening ports ----

func TestFilterListening(t *testing.T) {
	names := map[int32]string{10: "sshd", 20: "nginx", 30: "avahi-daemon", 40: "chronyd"}
	procName := func(pid int32) string { return names[pid] }
	conns := []RawConn{
		{Family: 2, Type: 1, IP: "0.0.0.0", Port: 22, Status: "LISTEN", Pid: 10},
		{Family: 10, Type: 1, IP: "::", Port: 22, Status: "LISTEN", Pid: 10},
		{Family: 2, Type: 1, IP: "10.0.0.5", Port: 22, RemotePort: 51234, Status: "ESTABLISHED", Pid: 11}, // a connection
		{Family: 2, Type: 1, IP: "*", Port: 443, Status: "LISTEN", Pid: 20},                               // lsof wildcard
		{Family: 30, Type: 1, IP: "*", Port: 443, Status: "LISTEN", Pid: 20},                              // IPv6 wildcard (macOS family)
		{Family: 2, Type: 1, IP: "0.0.0.0", Port: 443, Status: "LISTEN", Pid: 20},                         // duplicate after normalising
		{Family: 2, Type: 2, IP: "0.0.0.0", Port: 5353, Status: "NONE", Pid: 30},                          // bound UDP
		{Family: 2, Type: 2, IP: "10.0.0.5", Port: 40000, RemotePort: 123, Status: "NONE", Pid: 40},       // connected UDP
		{Family: 2, Type: 1, IP: "127.0.0.1", Port: 0, Status: "LISTEN", Pid: 20},                         // no port
		{Family: 2, Type: 5, IP: "0.0.0.0", Port: 1, Status: "", Pid: 1},                                  // not TCP / UDP
		{Family: 2, Type: 1, IP: "127.0.0.1", Port: 8080, Status: "listen", Pid: 0},                       // unknown process
	}
	got := FilterListening(conns, procName, 500)
	want := []protocol.ListeningPort{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"},
		{Protocol: "tcp", Address: "::", Port: 22, Process: "sshd"},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Process: "nginx"},
		{Protocol: "tcp", Address: "::", Port: 443, Process: "nginx"},
		{Protocol: "udp", Address: "0.0.0.0", Port: 5353, Process: "avahi-daemon"},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 8080, Process: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
	// The cap.
	var many []RawConn
	for port := uint32(1); port <= 700; port++ {
		many = append(many, RawConn{Family: 2, Type: 1, IP: "0.0.0.0", Port: port, Status: "LISTEN"})
	}
	if got := FilterListening(many, nil, MaxListeningPorts); len(got) != 500 || got[499].Port != 500 {
		t.Errorf("cap: %d entries", len(got))
	}
	if got := FilterListening(nil, nil, 10); got == nil || len(got) != 0 {
		t.Errorf("empty: %+v", got)
	}
}

// ---- the PowerShell scripts ----

// TestPowerShellScripts guards the properties the scripts rely on.
func TestPowerShellScripts(t *testing.T) {
	scripts := map[string]string{
		"PSAntivirus": PSAntivirus, "PSFirewall": PSFirewall, "PSBitLocker": PSBitLocker,
		"PSLocalAdmins": PSLocalAdmins, "PSLastPatch": PSLastPatch,
	}
	// Cmdlet verbs and tools that would change something. The collector is read-only.
	forbidden := []string{"set-", "remove-", "add-", "new-item", "disable-", "enable-", "stop-", "start-", "uninstall", "restart-",
		"invoke-expression", "iex ", "invoke-webrequest", "downloadstring", "-encodedcommand", "reg add", "reg delete", "sc.exe", "format-volume"}
	for name, s := range scripts {
		if !strings.HasSuffix(s, "\n") {
			t.Errorf("%s: no trailing newline", name)
		}
		if !strings.Contains(s, "ConvertTo-Json -Compress") {
			t.Errorf("%s: does not print JSON", name)
		}
		low := strings.ToLower(s)
		for _, f := range forbidden {
			if strings.Contains(low, f) {
				t.Errorf("%s: contains %q", name, f)
			}
		}
		// "powershell -Command -" runs stdin line by line: every line must
		// be a complete statement, so braces and parentheses balance per line.
		for i, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
			if strings.TrimSpace(line) == "" {
				t.Errorf("%s line %d: empty", name, i+1)
			}
			if strings.Count(line, "{") != strings.Count(line, "}") || strings.Count(line, "(") != strings.Count(line, ")") {
				t.Errorf("%s line %d: unbalanced: %s", name, i+1, line)
			}
			if strings.Count(line, "'")%2 != 0 {
				t.Errorf("%s line %d: odd number of single quotes", name, i+1)
			}
			if strings.Contains(line, "try{") && !strings.Contains(line, "}catch{") {
				t.Errorf("%s line %d: try without catch on the same line", name, i+1)
			}
		}
		for _, c := range s {
			if c > 0x7e || (c < 0x20 && c != '\n') {
				t.Errorf("%s: non-ASCII or control character %q", name, c)
			}
		}
	}
	// The invocation: script on stdin, never on the command line.
	cmd := PowerShell(PSFirewall, "A=b")
	wantArgs := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"}
	// A blank line ends the input: "-Command -" drops a final multi-line statement without it.
	if !strings.HasPrefix(cmd.Stdin, strings.TrimRight(PSFirewall, "\n")) || !strings.HasSuffix(cmd.Stdin, "\n\n") || strings.HasSuffix(cmd.Stdin, "\n\n\n") {
		t.Errorf("stdin must be the script plus one blank line: %q", cmd.Stdin[max(0, len(cmd.Stdin)-20):])
	}
	if got := PowerShellStdin("a |\n  b"); got != "a |\n  b\n\n" {
		t.Errorf("PowerShellStdin = %q", got)
	}
	if !reflect.DeepEqual(cmd.Args, wantArgs) || cmd.Stdin != PowerShellStdin(PSFirewall) || !reflect.DeepEqual(cmd.Env, []string{"A=b"}) ||
		!strings.HasSuffix(cmd.Path, `\System32\WindowsPowerShell\v1.0\powershell.exe`) || cmd.Timeout != PowerShellTimeout {
		t.Errorf("PowerShell(): %+v", cmd)
	}
}
