package software

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func find(items []protocol.SoftwareItem, id string) *protocol.SoftwareItem {
	for i := range items {
		if items[i].ID == id {
			return &items[i]
		}
	}
	return nil
}

func TestRegistryItems(t *testing.T) {
	var entries []RegistryEntry
	if err := json.Unmarshal([]byte(fixture(t, "registry_uninstall.json")), &entries); err != nil {
		t.Fatal(err)
	}
	items := RegistryItems(entries)
	// Skipped: the system component, the patch with a parent key, the entry
	// without a DisplayName.
	for _, it := range items {
		if strings.Contains(it.Name, "Click-to-Run") || strings.Contains(it.Name, "KB5044033") || it.ID == "AddressBook" {
			t.Errorf("entry should have been skipped: %+v", it)
		}
		if it.Source != protocol.SourceRegistry {
			t.Errorf("source = %q", it.Source)
		}
	}
	zip := find(items, "{23170F69-40C1-2702-2408-000001000000}")
	if zip == nil || zip.Name != "7-Zip 24.08 (x64 edition)" || zip.Version != "24.08.00.0" || zip.Publisher != "Igor Pavlov" || zip.InstallDate != "2024-10-03" {
		t.Fatalf("7-Zip = %+v", zip)
	}
	// An install date in any other format is dropped rather than passed on.
	if acro := find(items, "{AC76BA86-7AD7-1033-7B44-AC0F074E4100}"); acro == nil || acro.InstallDate != "" || acro.Publisher != "Adobe Systems Incorporated" {
		t.Fatalf("Acrobat = %+v", acro)
	}
	// Control characters never reach the report.
	weird := find(items, "WeirdName")
	if weird == nil || weird.Name != "Tool withcontrol" {
		t.Fatalf("control characters not cleaned: %+v (all: %+v)", weird, items)
	}
	// The same key in both views with the same version is one program.
	norm, _ := Normalize(items)
	git := 0
	for _, it := range norm {
		if it.ID == "Git_is1" {
			git++
		}
	}
	if git != 1 {
		t.Fatalf("Git reported %d times after normalisation", git)
	}
}

func TestParseWingetList(t *testing.T) {
	rows := ParseWingetTable(fixture(t, "winget_list.txt"))
	if len(rows) != 9 {
		t.Fatalf("rows = %d: %+v", len(rows), rows)
	}
	if r := rows[0]; r != (WingetRow{Name: "7-Zip 24.08 (x64)", ID: "7zip.7zip", Version: "24.08", Available: "24.09", Source: "winget"}) {
		t.Fatalf("row 0 = %+v", r)
	}
	if r := rows[2]; r.ID != "Google.Chrome" || r.Version != "130.0.6723.92" || r.Available != "" || r.Source != "winget" {
		t.Fatalf("row 2 = %+v", r)
	}
	// Truncated name, id containing "+".
	if r := rows[4]; r.ID != "Microsoft.VCRedist.2015+.x64" || r.Version != "14.40.33810.0" || r.Available != "14.42.34433.0" {
		t.Fatalf("row 4 = %+v", r)
	}
	// A wide (CJK) name must not shift the following columns.
	if r := rows[8]; r.ID != "Example.Ime" || r.Version != "2.0.1" || r.Source != "winget" {
		t.Fatalf("row 8 = %+v", r)
	}
	items := WingetItems(rows)
	if find(items, `ARP\Machine\X64\ContosoLegacy`) != nil {
		t.Fatal("ARP entries duplicate the registry and must be skipped")
	}
	if find(items, `MSIX\Microsoft.Paint_11.2408.30.0_x64__8wekyb3d8bbwe`) == nil {
		t.Fatal("MSIX entry missing")
	}
	vc := find(items, "Microsoft.VCRedist.2015+.x64")
	if vc == nil || strings.HasSuffix(vc.Name, "…") || vc.Source != protocol.SourceWinget {
		t.Fatalf("VCRedist = %+v", vc)
	}
}

func TestParseWingetTableVariants(t *testing.T) {
	// Localised headers, four columns (no "Available").
	rows := ParseWingetTable(fixture(t, "winget_list_de_4col.txt"))
	if len(rows) != 4 || rows[1].ID != "Git.Git" || rows[1].Version != "2.46.0" || rows[1].Source != "winget" || rows[1].Available != "" {
		t.Fatalf("german table = %+v", rows)
	}
	// Error text instead of a table.
	for _, name := range []string{"winget_list_error.txt", "winget_list_none.txt"} {
		if rows := ParseWingetTable(fixture(t, name)); len(rows) != 0 {
			t.Fatalf("%s: rows = %+v", name, rows)
		}
	}
	for _, junk := range []string{"", "\r\n\r\n", "----------", "Name Id\n-----\nx", strings.Repeat("-", 5000), "a\n" + strings.Repeat("-", 40) + "\n" + strings.Repeat("x", 100000)} {
		_ = ParseWingetTable(junk) // must not panic
	}
	// Exact-id query.
	if s := ParseWingetQuery(fixture(t, "winget_list_exact.txt"), "7ZIP.7zip"); !s.Installed || s.Version != "24.08" {
		t.Fatalf("exact query = %+v", s)
	}
	if s := ParseWingetQuery(fixture(t, "winget_list_none.txt"), "7zip.7zip"); s.Installed {
		t.Fatalf("absent package reported installed: %+v", s)
	}
	if s := ParseWingetQuery(fixture(t, "winget_list_exact.txt"), "Other.Id"); s.Installed {
		t.Fatal("a different id must not match")
	}
}

func TestParseInfoPlist(t *testing.T) {
	plist, err := ParseInfoPlistXML([]byte(fixture(t, "Info_calculator.plist")))
	if err != nil {
		t.Fatal(err)
	}
	it := AppItem("/System/Applications/Calculator.app", plist)
	if it.Name != "Calculator" || it.ID != "com.apple.calculator" || it.Version == "" || it.Source != protocol.SourceApp {
		t.Fatalf("item = %+v", it)
	}
	// Nested containers and non-string values are skipped, not confused with keys.
	xml := `<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "x"><plist version="1.0"><dict>
		<key>CFBundleDocumentTypes</key><array><dict><key>CFBundleName</key><string>WRONG</string></dict></array>
		<key>LSRequiresNativeExecution</key><true/>
		<key>CFBundleName</key><string>Right &amp; Proper</string>
		<key>CFBundleVersion</key><string>42</string>
		<key>Number</key><integer>7</integer>
	</dict></plist>`
	plist, err = ParseInfoPlistXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	it = AppItem("/Applications/Some Tool.app", plist)
	if it.Name != "Right & Proper" || it.Version != "42" {
		t.Fatalf("item = %+v", it)
	}
	// Without a usable plist the bundle name is the name.
	if it := AppItem("/Applications/Some Tool.app", nil); it.Name != "Some Tool" || it.Version != "" {
		t.Fatalf("fallback item = %+v", it)
	}
	for _, bad := range []string{"", "bplist00\x00\x01", "<html></html>", "<plist><array/></plist>", "<plist><dict><key>a</key>"} {
		if _, err := ParseInfoPlistXML([]byte(bad)); err == nil && bad != "<plist><dict><key>a</key>" {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParsePkgutil(t *testing.T) {
	ids := ParsePkgutilPkgs(fixture(t, "pkgutil_pkgs.txt"))
	if len(ids) != 12 || !strings.HasPrefix(ids[0], "com.apple.pkg.") {
		t.Fatalf("ids = %v", ids)
	}
	info := ParsePkgutilInfo(fixture(t, "pkgutil_info.txt"))
	if info.ID != "com.apple.pkg.CLTools_SDK_macOS13" || info.Version != "26.6.0.0.1781586384" || info.InstallTime != 1783591559 {
		t.Fatalf("info = %+v", info)
	}
	it := PkgutilItem(info.ID, info)
	if it.Source != protocol.SourcePkgutil || it.InstallDate != "2026-07-09" || it.Version != info.Version {
		t.Fatalf("item = %+v", it)
	}
	if got := ParsePkgutilInfo("No receipt for 'x' found at '/'.\n"); got.ID != "" {
		t.Fatalf("no receipt parsed as %+v", got)
	}
}

func TestParseBrewVersions(t *testing.T) {
	items := ParseBrewVersions(fixture(t, "brew_list_versions.txt"))
	if len(items) != 41 {
		t.Fatalf("items = %d", len(items))
	}
	if items[0].Name != "abseil" || items[0].Version != "20260817.0" || items[0].Source != protocol.SourceBrew || items[0].ID != "abseil" {
		t.Fatalf("first = %+v", items[0])
	}
	// Several installed versions: the last one listed is the newest.
	multi := ParseBrewVersions("python@3.12 3.12.5 3.12.7\n==> Casks\nWarning: something\n")
	if len(multi) != 1 || multi[0].Version != "3.12.7" {
		t.Fatalf("multi = %+v", multi)
	}
	if s := ParseBrewQuery("wget 1.24.5\n"); !s.Installed || s.Version != "1.24.5" {
		t.Fatalf("query = %+v", s)
	}
	if s := ParseBrewQuery(""); s.Installed {
		t.Fatal("empty output means not installed")
	}
}

func TestParseDpkgQuery(t *testing.T) {
	items := ParseDpkgQuery(fixture(t, "dpkg_query_debian12.txt"))
	if len(items) < 80 {
		t.Fatalf("items = %d", len(items))
	}
	bash := find(items, "bash")
	if bash == nil || bash.Version != "5.2.15-2+b13" || bash.Publisher != "Matthias Klose <doko@debian.org>" || bash.Source != protocol.SourceDpkg {
		t.Fatalf("bash = %+v", bash)
	}
	// Removed-but-configured ("rc") and half-installed packages are not installed software.
	extra := "gone\tgone\t1.0\tSomeone\trc \nbroken\tbroken\t2.0\tSomeone\tiU \nlibc6:arm64\tlibc6\t2.36-9\tGNU Libc Maintainers\tii \nshort line\n"
	items = ParseDpkgQuery(extra)
	if len(items) != 1 || items[0].Name != "libc6" || items[0].ID != "libc6:arm64" {
		t.Fatalf("status filter: %+v", items)
	}
	if s := ParseDpkgStatus("ii \t5.2.15-2+b13\n"); !s.Installed || s.Version != "5.2.15-2+b13" {
		t.Fatalf("status = %+v", s)
	}
	for _, out := range []string{"", "rc \t1.0\n", "un \t\n", "dpkg-query: no packages found matching x\n"} {
		if s := ParseDpkgStatus(out); s.Installed {
			t.Errorf("%q reported installed", out)
		}
	}
}

func TestParseRpmQa(t *testing.T) {
	items := ParseRpmQa(fixture(t, "rpm_qa_rocky9.txt"))
	if len(items) < 130 {
		t.Fatalf("items = %d", len(items))
	}
	for _, it := range items {
		if it.Name == "gpg-pubkey" {
			t.Fatal("gpg-pubkey is not software")
		}
		if it.Source != protocol.SourceRPM || it.Version == "" || it.InstallDate == "" {
			t.Fatalf("incomplete item %+v", it)
		}
	}
	bash := find(items, "bash.aarch64")
	if bash == nil || bash.Name != "bash" || bash.Version != "5.1.8-6.el9_1" || bash.Publisher != "Rocky Enterprise Software Foundation" || bash.InstallDate != "2023-11-19" {
		t.Fatalf("bash = %+v", bash)
	}
	// Epoch is part of the version only when it is not zero.
	items = ParseRpmQa("findutils\t1\t4.8.0\t6.el9\taarch64\t(none)\t1700432740\ngpg-pubkey\t0\t350d275d\t6279464b\t(none)\t(none)\t1700432750\n")
	if len(items) != 1 || items[0].Version != "1:4.8.0-6.el9" || items[0].Publisher != "" || items[0].ID != "findutils.aarch64" {
		t.Fatalf("epoch: %+v", items)
	}
	if s := ParseRpmQuery("0\t5.1.8\t6.el9_1\n"); !s.Installed || s.Version != "5.1.8-6.el9_1" {
		t.Fatalf("query = %+v", s)
	}
	// Two installed kernels: the newest is reported.
	if s := ParseRpmQuery("0\t5.14.0\t362.el9\n0\t5.14.0\t427.el9\n"); s.Version != "5.14.0-427.el9" {
		t.Fatalf("multi = %+v", s)
	}
	if s := ParseRpmQuery("package nonexistent is not installed\n"); s.Installed {
		t.Fatal("not installed text parsed as installed")
	}
}

func TestParseSnapAndFlatpak(t *testing.T) {
	snaps := ParseSnapList(fixture(t, "snap_list.txt"))
	if len(snaps) != 5 {
		t.Fatalf("snaps = %+v", snaps)
	}
	ff := find(snaps, "firefox")
	if ff == nil || ff.Version != "131.0.2-1" || ff.Publisher != "mozilla" || ff.Source != protocol.SourceSnap {
		t.Fatalf("firefox = %+v", ff)
	}
	if local := find(snaps, "my-local-snap"); local == nil || local.Publisher != "" {
		t.Fatalf("local snap = %+v", local)
	}
	if got := ParseSnapList("No snaps are installed yet. Try 'snap install hello-world'.\n"); len(got) != 0 && got[0].Name == "Name" {
		t.Fatalf("header leaked: %+v", got)
	}
	flat := ParseFlatpakList(fixture(t, "flatpak_list.txt"))
	if len(flat) != 3 {
		t.Fatalf("flatpaks = %+v", flat)
	}
	gimp := find(flat, "org.gimp.GIMP")
	if gimp == nil || gimp.Name != "GIMP" || gimp.Version != "2.10.38" || gimp.Source != protocol.SourceFlatpak {
		t.Fatalf("gimp = %+v", gimp)
	}
	if nv := find(flat, "com.example.NoVersion"); nv == nil || nv.Version != "" {
		t.Fatalf("no-version app = %+v", nv)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.2", "1.2.0", 0},
		{"1.2", "1.2.1", -1},
		{"1.10", "1.9", 1},
		{"24.08", "24.9", -1},
		{"v2.0.1", "2.0.1", 0},
		{"130.0.6723.92", "130.0.6723.117", -1},
		{"5.2.15-2+b13", "5.2.15-2", 1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.a", 1},
		{"3.0.22-1~deb12u2", "3.0.20-1~deb12u2", 1},
		{"99999999999999999999999.1", "99999999999999999999998.9", 1},
		{"", "", 0},
		{"", "1", -1},
		{"2.0-beta", "2.0-BETA", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCleanAndLines(t *testing.T) {
	if got := Clean("  a\x00b\tc\x1b[0m  ", 100); got != "ab c[0m" {
		t.Fatalf("Clean = %q", got)
	}
	if got := Clean("héllo wörld", 3); got != "hé" {
		t.Fatalf("Clean cut = %q", got)
	}
	if got := Clean(string([]byte{0xff, 'a'}), 10); !strings.HasSuffix(got, "a") || len(got) != 4 {
		t.Fatalf("invalid UTF-8 not replaced: %q", got)
	}
	lines := Lines("\xef\xbb\xbfone\r\n  - \r  \\ \rtwo\r\nthree")
	if len(lines) != 3 || lines[0] != "one" || lines[1] != "two" || lines[2] != "three" {
		t.Fatalf("Lines = %q", lines)
	}
}
