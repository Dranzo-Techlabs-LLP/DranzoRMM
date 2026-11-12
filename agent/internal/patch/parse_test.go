package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func findPatch(list []protocol.PendingPatch, id string) *protocol.PendingPatch {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

func TestEncodeDecodeID(t *testing.T) {
	cases := map[string][2]string{
		"apt:openssl":      {"apt", "openssl"},
		"apt:libc6@3Ai386": {"apt", "libc6:i386"},
		"dnf:bash.aarch64": {"dnf", "bash.aarch64"},
		"softwareupdate:macOS@20Sonoma@2014.6.1-23G93":           {"softwareupdate", "macOS Sonoma 14.6.1-23G93"},
		"softwareupdate:Pro@20Video@20Formats@2C@20@28beta@29-1": {"softwareupdate", "Pro Video Formats, (beta)-1"},
		"winget:Microsoft.VCRedist.2015+.x64":                    {"winget", "Microsoft.VCRedist.2015+.x64"},
		"brew:node@4020":                                         {"brew", "node@20"},
		"wua:3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11":               {"wua", "3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11"},
	}
	for id, parts := range cases {
		got, ok := EncodeID(parts[0], parts[1])
		if !ok || got != id {
			t.Errorf("EncodeID(%q, %q) = %q, %v; want %q", parts[0], parts[1], got, ok, id)
		}
		if !protocol.ValidPackageID(got) {
			t.Errorf("%q does not match the protocol's update id pattern", got)
		}
		source, name, ok := DecodeID(id)
		if !ok || source != parts[0] || name != parts[1] {
			t.Errorf("DecodeID(%q) = %q, %q, %v", id, source, name, ok)
		}
	}
	// Non-ASCII labels survive the round trip.
	id, ok := EncodeID(SourceSoftwareUpdate, "Mise à jour – été")
	if _, name, ok2 := DecodeID(id); !ok || !ok2 || name != "Mise à jour – été" {
		t.Fatalf("round trip failed: %q %v %v", id, ok, ok2)
	}
	if _, ok := EncodeID(SourceApt, ""); ok {
		t.Error("empty name accepted")
	}
	if _, ok := EncodeID(SourceSoftwareUpdate, strings.Repeat(" ", 100)); ok {
		t.Error("an id longer than the protocol allows was produced")
	}
	for _, bad := range []string{
		"", "openssl", "apt:", ":openssl", "yum:openssl", "apt:a@", "apt:a@2", "apt:a@zz", "apt:a@2a", "apt:a b", "-apt:x",
		"apt:x; rm -rf /", "apt:$(id)", "APT:openssl",
	} {
		if s, n, ok := DecodeID(bad); ok {
			t.Errorf("DecodeID(%q) accepted: %q %q", bad, s, n)
		}
	}
}

func TestParseAptUpgradable(t *testing.T) {
	ups := ParseAptUpgradable(fixture(t, "apt_list_upgradable_debian12.txt"))
	if len(ups) != 2 {
		t.Fatalf("ups = %+v", ups)
	}
	want := AptUpgrade{Name: "libssl3", CurrentVersion: "3.0.20-1~deb12u2", NewVersion: "3.0.22-1~deb12u2", Arch: "arm64", Origin: "oldstable-security", Security: true}
	if ups[0] != want {
		t.Fatalf("ups[0] = %+v", ups[0])
	}
	// Ubuntu style, several suites, non-security, warnings in between.
	out := "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\nListing... Done\n" +
		"curl/jammy-updates,jammy-security 7.81.0-1ubuntu1.18 amd64 [upgradable from: 7.81.0-1ubuntu1.16]\n" +
		"vim/jammy-updates 2:8.2.3995-1ubuntu2.19 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.17]\n" +
		"N: There is 1 additional version. Please use the '-a' switch to see it\n"
	ups = ParseAptUpgradable(out)
	if len(ups) != 2 || !ups[0].Security || ups[1].Security || ups[1].Name != "vim" || ups[1].NewVersion != "2:8.2.3995-1ubuntu2.19" {
		t.Fatalf("ubuntu: %+v", ups)
	}
	if got := ParseAptUpgradable("Listing...\n"); len(got) != 0 {
		t.Fatalf("empty list: %+v", got)
	}
}

func TestParseAptSimulate(t *testing.T) {
	ups := ParseAptSimulate(fixture(t, "apt_simulate_debian12.txt"))
	if len(ups) != 2 {
		t.Fatalf("ups = %+v", ups)
	}
	want := AptUpgrade{Name: "openssl", CurrentVersion: "3.0.20-1~deb12u2", NewVersion: "3.0.22-1~deb12u2", Arch: "arm64", Origin: "Debian-Security:12/oldstable-security", Security: true}
	if ups[1] != want {
		t.Fatalf("ups[1] = %+v", ups[1])
	}
	// A newly installed dependency (no current version) is not an update;
	// several origins are kept together.
	out := "Inst linux-image-6.1.0-25-amd64 (6.1.106-3 Debian:12.7/stable [amd64])\n" +
		"Inst base-files [12.4+deb12u6] (12.4+deb12u7 Debian:12.7/stable, Debian:12-updates/stable-updates [amd64])\n" +
		"Conf base-files (12.4+deb12u7 Debian:12.7/stable [amd64])\n"
	ups = ParseAptSimulate(out)
	if len(ups) != 1 || ups[0].Name != "base-files" || ups[0].Security || ups[0].Arch != "amd64" || !strings.Contains(ups[0].Origin, "stable-updates") {
		t.Fatalf("simulate: %+v", ups)
	}
}

func TestParseAptHistoryLast(t *testing.T) {
	loc := time.FixedZone("test", 3600)
	got, ok := ParseAptHistoryLast(fixture(t, "apt_history.log"), loc)
	if !ok || !got.Equal(time.Date(2026, 11, 11, 17, 16, 43, 0, loc)) {
		t.Fatalf("got %v %v", got, ok)
	}
	// The last finished transaction counts; an unfinished one has no End-Date.
	log := "Start-Date: 2024-01-01  10:00:00\nEnd-Date: 2024-01-01  10:00:05\n\nStart-Date: 2024-02-02  11:00:00\nEnd-Date: 2024-02-02  11:01:00\n\nStart-Date: 2024-03-03  12:00:00\nEnd-Date: garbage\n"
	got, ok = ParseAptHistoryLast(log, time.UTC)
	if !ok || !got.Equal(time.Date(2024, 2, 2, 11, 1, 0, 0, time.UTC)) {
		t.Fatalf("got %v %v", got, ok)
	}
	if _, ok := ParseAptHistoryLast("", time.UTC); ok {
		t.Fatal("empty log has no date")
	}
}

func TestParseDnfCheckUpdate(t *testing.T) {
	ups := ParseDnfCheckUpdate(fixture(t, "dnf_check_update_rocky9.txt"))
	if len(ups) != 112 {
		t.Fatalf("updates = %d", len(ups))
	}
	byName := map[string]DnfUpdate{}
	for _, u := range ups {
		byName[u.NameArch()] = u
		if u.Name == "" || u.Arch == "" || u.Version == "" || u.Repo == "" {
			t.Fatalf("incomplete: %+v", u)
		}
	}
	if u := byName["bash.aarch64"]; u.Version != "5.1.8-9.el9" || u.Repo != "baseos" {
		t.Fatalf("bash = %+v", u)
	}
	// Epoch stays part of the version.
	if u := byName["findutils.aarch64"]; u.Version != "1:4.8.0-7.el9" {
		t.Fatalf("findutils = %+v", u)
	}
	// Wrapped long names, the obsoletes section and informational lines.
	out := "Last metadata expiration check: 0:10:11 ago on Mon Nov  4 10:00:00 2024.\n\n" +
		"kernel.x86_64                          5.14.0-427.42.1.el9_4              baseos\n" +
		"java-17-openjdk-headless-fastdebug-with-a-very-long-name.x86_64\n" +
		"                                       1:17.0.13.0.11-3.el9               appstream\n" +
		"not-a-package-line some words here that are longer\n" +
		"python3.11-libs.x86_64                 3.11.9-7.el9                       appstream\n" +
		"Obsoleting Packages\n" +
		"grub2-tools.x86_64                     1:2.06-80.el9                      baseos\n" +
		"    grub2-tools.x86_64                 1:2.06-70.el9                      @anaconda\n" +
		"Security: kernel-core-5.14.0-427.42.1.el9_4.x86_64 is an installed security update\n"
	ups = ParseDnfCheckUpdate(out)
	if len(ups) != 3 {
		t.Fatalf("variants: %+v", ups)
	}
	if ups[1].Name != "java-17-openjdk-headless-fastdebug-with-a-very-long-name" || ups[1].Version != "1:17.0.13.0.11-3.el9" || ups[1].Repo != "appstream" {
		t.Fatalf("wrapped = %+v", ups[1])
	}
	if ups[2].Name != "python3.11-libs" || ups[2].Arch != "x86_64" {
		t.Fatalf("dotted name = %+v", ups[2])
	}
	if got := ParseDnfCheckUpdate(""); len(got) != 0 {
		t.Fatalf("no updates: %+v", got)
	}
}

func TestParseDnfUpdateinfo(t *testing.T) {
	sev := ParseDnfUpdateinfo(fixture(t, "dnf_updateinfo_security_rocky9.txt"))
	if len(sev) < 30 {
		t.Fatalf("packages with advisories = %d", len(sev))
	}
	// curl-minimal has Moderate and Important advisories: the highest wins.
	if sev["curl-minimal.aarch64"] != SeverityImportant {
		t.Fatalf("curl-minimal = %q", sev["curl-minimal.aarch64"])
	}
	if sev["ca-certificates.noarch"] != SeverityCritical || sev["binutils-gold.aarch64"] != SeverityModerate {
		t.Fatalf("ca-certificates %q, binutils-gold %q", sev["ca-certificates.noarch"], sev["binutils-gold.aarch64"])
	}
	// Epoch in the NEVRA, older dnf wording, and non-security advisories.
	out := "RHSA-2024:1234 Important/Sec. openssl-1:3.0.7-25.el9_3.x86_64\n" +
		"RHSA-2024:9999 security      zlib-1.2.11-41.el9.x86_64\n" +
		"RHBA-2024:1111 bugfix        bash-5.1.8-9.el9.x86_64\n" +
		"RHEA-2024:2222 enhancement   tzdata-2024b-2.el9.noarch\n"
	sev = ParseDnfUpdateinfo(out)
	if len(sev) != 2 || sev["openssl.x86_64"] != SeverityImportant || sev["zlib.x86_64"] != SeverityUnspecified {
		t.Fatalf("variants: %+v", sev)
	}
}

func TestParseSoftwareUpdateListNewFormat(t *testing.T) {
	items := ParseSoftwareUpdateList(fixture(t, "softwareupdate_list_new.txt"))
	if len(items) != 4 {
		t.Fatalf("items = %+v", items)
	}
	want := SoftwareUpdateItem{Label: "macOS Sonoma 14.6.1-23G93", Title: "macOS Sonoma 14.6.1", Version: "14.6.1", SizeBytes: 1568310 * 1024, Recommended: true, Restart: true}
	if items[0] != want {
		t.Fatalf("items[0] = %+v", items[0])
	}
	if it := items[1]; it.Label != "Command Line Tools for Xcode-15.3" || it.Title != "Command Line Tools for Xcode" || it.Restart || !it.Recommended {
		t.Fatalf("items[1] = %+v", it)
	}
	// A comma inside the title.
	if it := items[3]; it.Title != "Pro Video Formats, with HEVC" || it.Version != "2.3.2" || it.Recommended || it.SizeBytes != 7300*1024 {
		t.Fatalf("items[3] = %+v", it)
	}
}

func TestParseSoftwareUpdateListOldFormat(t *testing.T) {
	items := ParseSoftwareUpdateList(fixture(t, "softwareupdate_list_old.txt"))
	if len(items) != 3 {
		t.Fatalf("items = %+v", items)
	}
	want := SoftwareUpdateItem{Label: "Security Update 2019-004-10.13.6", Title: "Security Update 2019-004", Version: "10.13.6", SizeBytes: 1942411 * 1024, Recommended: true, Restart: true}
	if items[0] != want {
		t.Fatalf("items[0] = %+v", items[0])
	}
	if it := items[1]; it.Label != "iTunesX-12.8.2" || it.Title != "iTunes" || it.Version != "12.8.2" || it.Restart || !it.Recommended {
		t.Fatalf("items[1] = %+v", it)
	}
	if it := items[2]; it.Recommended || it.Restart || it.Version != "6.21" {
		t.Fatalf("items[2] = %+v", it)
	}
	if got := ParseSoftwareUpdateList(fixture(t, "softwareupdate_list_none.txt")); len(got) != 0 {
		t.Fatalf("no updates: %+v", got)
	}
	// A label without a detail line still yields an item.
	if got := ParseSoftwareUpdateList("* Label: Lonely-1.0\n* Label: Other-2.0\n"); len(got) != 2 || got[0].Title != "Lonely-1.0" {
		t.Fatalf("no detail: %+v", got)
	}
	for title, want := range map[string]string{
		"macOS Sonoma 14.6.1":                      CategoryUpdate,
		"Security Update 2019-004":                 CategorySecurity,
		"macOS Rapid Security Response 13.4.1 (a)": CategorySecurity,
		"XProtectPlistConfigData":                  CategorySecurity,
		"Command Line Tools for Xcode":             CategoryTool,
		"Safari":                                   CategoryApplication,
	} {
		if got := softwareUpdateCategory(title); got != want {
			t.Errorf("category(%q) = %s, want %s", title, got, want)
		}
	}
}

func TestSoftwareUpdateFailure(t *testing.T) {
	failures := []string{
		"Software Update Tool\n\nFinding available software\nDownloading macOS Sonoma 14.6.1\nPassword: \nFailed to authenticate\n",
		"softwareupdate: Not authorized to install updates: a volume owner is required.\n",
		"macOS Sonoma 14.6.1-23G93: No such update\nNo updates are available.\n",
		"Error installing updates.\n",
	}
	for _, out := range failures {
		if SoftwareUpdateFailure(out) == "" {
			t.Errorf("failure not detected in %q", out)
		}
	}
	if msg := SoftwareUpdateFailure(failures[0]); !strings.Contains(msg, "volume owner") || !strings.Contains(msg, "MDM") {
		t.Fatalf("authorisation failure is not explained: %q", msg)
	}
	ok := "Software Update Tool\n\nFinding available software\n\nDownloading Safari\nDownloaded Safari\nInstalling Safari\nDone with Safari\nDone.\n"
	if msg := SoftwareUpdateFailure(ok); msg != "" {
		t.Fatalf("success reported as failure: %q", msg)
	}
}

func TestParseBrewOutdated(t *testing.T) {
	// Real output of "brew outdated --json=v2" on the development Mac.
	out, err := ParseBrewOutdated(fixture(t, "brew_outdated_v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 10 {
		t.Fatalf("outdated = %d", len(out))
	}
	if out[0].Name != "ada-url" || out[0].Installed != "3.4.4" || out[0].Current != "4.0.0_1" || out[0].Cask || out[0].Pinned {
		t.Fatalf("first = %+v", out[0])
	}
	last := out[len(out)-1]
	if last.Name != "libreoffice" || !last.Cask || last.Installed != "26.2.3" || last.Current != "26.8.2" {
		t.Fatalf("cask = %+v", last)
	}
	// Older Homebrew: a cask's installed version is a plain string; warnings before the JSON.
	old := "Warning: something\n" + `{"formulae":[{"name":"wget","installed_versions":["1.21","1.21.4"],"current_version":"1.24.5","pinned":true,"pinned_version":"1.21.4"}],"casks":[{"name":"firefox","installed_versions":"120.0","current_version":"131.0"}]}`
	out, err = ParseBrewOutdated(old)
	if err != nil || len(out) != 2 || !out[0].Pinned || out[0].Installed != "1.21.4" || out[1].Installed != "120.0" || !out[1].Cask {
		t.Fatalf("old format: %+v %v", out, err)
	}
	if out, err := ParseBrewOutdated(`{"formulae":[],"casks":[]}`); err != nil || len(out) != 0 {
		t.Fatalf("nothing outdated: %+v %v", out, err)
	}
	for _, bad := range []string{"", "Error: something", `{"formulae": 5}`} {
		if _, err := ParseBrewOutdated(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseWUAScan(t *testing.T) {
	scan, err := ParseWUAScan(fixture(t, "wua_scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The entry whose id is not a GUID is dropped.
	if len(scan.Pending) != 4 {
		t.Fatalf("pending = %+v", scan.Pending)
	}
	if !scan.RebootRequired || scan.LastInstallAt == nil || !scan.LastInstallAt.Equal(time.Date(2024, 10, 9, 3, 12, 44, 0, time.UTC)) {
		t.Fatalf("reboot %v last %v", scan.RebootRequired, scan.LastInstallAt)
	}
	cu := findPatch(scan.Pending, "wua:3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11")
	if cu == nil || cu.KB != "KB5044285" || cu.Category != CategorySecurity || cu.Severity != SeverityCritical || cu.Source != SourceWUA ||
		cu.SizeBytes == nil || *cu.SizeBytes != 734003200 || cu.RequiresReboot == nil || !*cu.RequiresReboot {
		t.Fatalf("cumulative update = %+v", cu)
	}
	// The category comes from the classification id, so a localised name does not matter.
	def := findPatch(scan.Pending, "wua:a32ca1d0-ddd4-486b-b708-d941db4f1051")
	if def == nil || def.Category != CategoryDefinition || def.Severity != SeverityUnspecified || def.KB != "KB2267602" || def.RequiresReboot == nil || *def.RequiresReboot {
		t.Fatalf("definition update = %+v", def)
	}
	// A single category object instead of a list, null severity, "can request" reboot.
	drv := findPatch(scan.Pending, "wua:7c0e0f5b-2f46-4b0a-9c5e-1d2a3b4c5d6e")
	if drv == nil || drv.Category != CategoryDriver || drv.KB != "" || drv.SizeBytes != nil || drv.RequiresReboot != nil {
		t.Fatalf("driver = %+v", drv)
	}
	// A bare string instead of a list of KB numbers.
	net := findPatch(scan.Pending, "wua:11111111-2222-3333-4444-555555555555")
	if net == nil || net.KB != "KB5042667" || net.Category != CategoryUpdate || net.Severity != SeverityImportant {
		t.Fatalf(".NET update = %+v", net)
	}
	for _, p := range scan.Pending {
		if !protocol.ValidPackageID(p.ID) {
			t.Errorf("invalid id %q", p.ID)
		}
	}
	if _, err := ParseWUAScan(fixture(t, "wua_scan_error.json")); err == nil || !strings.Contains(err.Error(), "0x8024402C") {
		t.Fatalf("error result: %v", err)
	}
	for _, bad := range []string{"", "no json here", "{", `{"ok": "yes"}`} {
		if _, err := ParseWUAScan(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if scan, err := ParseWUAScan(`{"ok":true,"updates":[],"rebootRequired":false,"lastInstallAt":""}`); err != nil || len(scan.Pending) != 0 || scan.LastInstallAt != nil {
		t.Fatalf("empty scan: %+v %v", scan, err)
	}
	if scan, err := ParseWUAScan(`{"ok":true,"updates":null}`); err != nil || len(scan.Pending) != 0 {
		t.Fatalf("null updates: %+v %v", scan, err)
	}
}

func TestParseWUAInstall(t *testing.T) {
	res, err := ParseWUAInstall(fixture(t, "wua_install.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.RebootRequired || len(res.Items) != 3 {
		t.Fatalf("res = %+v", res)
	}
	if it := res.Items[0]; it.ID != "wua:3f0a2d6c-1b7e-4c55-9e0a-6d2c9b1f7a11" || !it.OK || it.Error != "" {
		t.Fatalf("items[0] = %+v", it)
	}
	if it := res.Items[1]; it.OK || !strings.Contains(it.Error, "0x80070643") {
		t.Fatalf("items[1] = %+v", it)
	}
	if it := res.Items[2]; it.OK || !strings.Contains(it.Error, "not pending") {
		t.Fatalf("items[2] = %+v", it)
	}
	if _, err := ParseWUAInstall(`{"ok":false,"error":"Access is denied."}`); err == nil || !strings.Contains(err.Error(), "Access is denied") {
		t.Fatalf("err = %v", err)
	}
	// A single result object where a list is expected (PowerShell 5.1).
	res, err = ParseWUAInstall(`{"ok":true,"rebootRequired":false,"results":{"id":"11111111-2222-3333-4444-555555555555","ok":true,"error":"","rebootRequired":true}}`)
	if err != nil || len(res.Items) != 1 || !res.Items[0].OK || !res.RebootRequired {
		t.Fatalf("single result: %+v %v", res, err)
	}
}

// TestWUAScriptsShape checks the properties the scripts need to work when
// PowerShell reads them from standard input (see the comment in wua.go).
func TestWUAScriptsShape(t *testing.T) {
	for name, script := range map[string]string{"scan": wuaScanScript, "install": wuaInstallScript} {
		if !strings.HasPrefix(script, "& {\n") {
			t.Errorf("%s: the script must be one \"& { ... }\" statement", name)
		}
		if !strings.HasSuffix(script, "\n}\n\n\n") {
			t.Errorf("%s: the statement must be followed by blank lines so that PowerShell runs it", name)
		}
		body := strings.TrimRight(script, "\n")
		for i, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == "" {
				t.Errorf("%s: line %d is blank; a blank line would end the statement early", name, i+1)
			}
			if strings.Contains(line, "\t") || strings.Contains(line, "\r") {
				t.Errorf("%s: line %d contains a tab or carriage return", name, i+1)
			}
		}
		for i := 0; i < len(script); i++ {
			if script[i] > 126 {
				t.Fatalf("%s: non-ASCII byte at offset %d (the console code page would garble it)", name, i)
			}
		}
		for _, pair := range [][2]string{{"{", "}"}, {"(", ")"}, {"[", "]"}} {
			if strings.Count(script, pair[0]) != strings.Count(script, pair[1]) {
				t.Errorf("%s: unbalanced %s %s", name, pair[0], pair[1])
			}
		}
		if strings.Count(script, "'")%2 != 0 {
			t.Errorf("%s: unbalanced quotes", name)
		}
		// The documented COM API, no third-party module, nothing hidden.
		for _, want := range []string{"Microsoft.Update.Session", "CreateUpdateSearcher", "IsInstalled=0 and IsHidden=0", "ConvertTo-Json"} {
			if !strings.Contains(script, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
		for _, banned := range []string{"PSWindowsUpdate", "Install-Module", "Import-Module", "Invoke-Expression", "iex ", "FromBase64String", "DownloadString", "Set-MpPreference", "-EncodedCommand", "WindowStyle"} {
			if strings.Contains(script, banned) {
				t.Errorf("%s: contains %q", name, banned)
			}
		}
	}
	for _, want := range []string{"CreateUpdateDownloader", "CreateUpdateInstaller", "DRANZO_WUA_IDS", "DRANZO_WUA_ALL", "AcceptEula", "CanRequestUserInput"} {
		if !strings.Contains(wuaInstallScript, want) {
			t.Errorf("install script: missing %q", want)
		}
	}
	if strings.Join(PowerShellArgs, " ") != "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -" {
		t.Fatalf("PowerShellArgs = %v", PowerShellArgs)
	}
}
