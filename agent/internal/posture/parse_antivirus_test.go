package posture

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var fixedNow = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func isUnsupported(err error) bool {
	var ue *UnsupportedError
	return errors.As(err, &ue) && errors.Is(err, platform.ErrUnsupported)
}

func TestDecodeProductState(t *testing.T) {
	cases := []struct {
		state             uint32
		enabled, upToDate bool
	}{
		{397568, true, true},   // 0x061100 Defender on, current
		{393472, false, true},  // 0x060100 Defender off, current
		{397584, true, false},  // 0x061110 Defender on, out of date
		{393488, false, false}, // 0x060110 Defender off, out of date
		{397312, true, true},   // 0x061000
		{393216, false, true},  // 0x060000
		{401664, false, true},  // 0x062100 snoozed counts as off
		{266240, true, true},   // 0x041000 third party on, current
		{262144, false, true},  // 0x040000 third party off, current
		{266256, true, false},  // 0x041010 third party on, out of date
		{262160, false, false}, // 0x040010 third party off, out of date
		{331776, true, true},   // 0x051000
		{0, false, true},
	}
	for _, c := range cases {
		enabled, upToDate := DecodeProductState(c.state)
		if enabled != c.enabled || upToDate != c.upToDate {
			t.Errorf("state %d (0x%06x): got enabled=%v upToDate=%v, want %v %v", c.state, c.state, enabled, upToDate, c.enabled, c.upToDate)
		}
	}
}

func TestParseWindowsAntivirus(t *testing.T) {
	cases := []struct {
		file string
		want []protocol.AntivirusProduct
	}{
		{"win_av_client_defender.json", []protocol.AntivirusProduct{
			{Name: "Windows Defender", Enabled: true, UpToDate: true, SignatureVersion: "1.421.612.0", Source: "wsc"},
		}},
		// Duplicate registration: the enabled entry wins. Defender is passive.
		{"win_av_multiple.json", []protocol.AntivirusProduct{
			{Name: "Windows Defender", Enabled: false, UpToDate: true, SignatureVersion: "1.419.100.0", Source: "wsc"},
			{Name: "Sophos Anti-Virus", Enabled: true, UpToDate: true, Source: "wsc"},
			{Name: "Old Scanner", Enabled: false, UpToDate: false, Source: "wsc"},
		}},
		// Windows PowerShell prints a one-element list as a bare object.
		{"win_av_single_object.json", []protocol.AntivirusProduct{
			{Name: "Windows Defender", Enabled: true, UpToDate: false, Source: "wsc"},
		}},
		// Server SKU: no Security Center, Defender status is used. Real-time
		// protection off means not enabled.
		{"win_av_server.json", []protocol.AntivirusProduct{
			{Name: "Microsoft Defender Antivirus", Enabled: false, UpToDate: true, SignatureVersion: "1.421.612.0", Source: "defender"},
		}},
		{"win_av_server_stale.json", []protocol.AntivirusProduct{
			{Name: "Microsoft Defender Antivirus", Enabled: true, UpToDate: false, SignatureVersion: "1.401.5.0", Source: "defender"},
		}},
		{"win_av_none.json", []protocol.AntivirusProduct{}},
	}
	for _, c := range cases {
		got, err := ParseWindowsAntivirus(fixture(t, c.file), fixedNow)
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.file, got, c.want)
		}
	}
	if _, err := ParseWindowsAntivirus(fixture(t, "win_av_unavailable.json"), fixedNow); !isUnsupported(err) {
		t.Errorf("unavailable: want unsupported, got %v", err)
	}
	if _, err := ParseWindowsAntivirus([]byte("not json"), fixedNow); err == nil || isUnsupported(err) {
		t.Errorf("garbage: want a plain error, got %v", err)
	}
}

func TestExtractJSON(t *testing.T) {
	good := map[string]string{
		`{"a":1}`:                               `{"a":1}`,
		"\xEF\xBB\xBF{\"a\":1}\r\n":             `{"a":1}`,
		"WARNING: something\r\n{\"a\":1}\r\n":   `{"a":1}`,
		"[1,2]\n":                               `[1,2]`,
		"PS C:\\> \n{\"a\":{\"b\":[1]}}\nPS>\n": `{"a":{"b":[1]}}`,
	}
	for in, want := range good {
		got, err := ExtractJSON(in)
		if err != nil || string(got) != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "   \n", "error text", "{broken", "42", `"str"`} {
		if _, err := ExtractJSON(in); err == nil {
			t.Errorf("%q: accepted", in)
		}
	}
}

func TestGatekeeperAndVersions(t *testing.T) {
	if on, ok := ParseGatekeeperStatus("assessments enabled\n"); !ok || !on {
		t.Error("enabled not parsed")
	}
	if on, ok := ParseGatekeeperStatus("assessments disabled\n"); !ok || on {
		t.Error("disabled not parsed")
	}
	if _, ok := ParseGatekeeperStatus("spctl: command failed"); ok {
		t.Error("garbage accepted")
	}
	versions := [][3]string{
		{"", "5372", "5372"}, {"5372", "", "5372"}, {"5290", "5372", "5372"},
		{"5372", "999", "5372"}, {"2.10", "2.9", "2.10"}, {"1.0", "1.0.1", "1.0.1"}, {"", "", ""},
	}
	for _, v := range versions {
		if got := HigherVersion(v[0], v[1]); got != v[2] {
			t.Errorf("HigherVersion(%q,%q) = %q, want %q", v[0], v[1], got, v[2])
		}
	}
}

func TestMacAntivirus(t *testing.T) {
	yes, no := true, false
	// Plain Mac: XProtect plus the Gatekeeper state.
	got := MacAntivirus("5372", nil, &yes, nil)
	want := []protocol.AntivirusProduct{
		{Name: "XProtect", Enabled: true, UpToDate: true, SignatureVersion: "5372", Source: "xprotect"},
		{Name: "Gatekeeper", Enabled: true, UpToDate: true, Source: "xprotect"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("plain:\n got %+v\nwant %+v", got, want)
	}
	// Automatic XProtect data installation switched off, Gatekeeper off,
	// two third-party products.
	known := []protocol.AntivirusProduct{
		{Name: "CrowdStrike Falcon", Enabled: true, UpToDate: true, Source: "known_av"},
		{Name: "Malwarebytes", Enabled: false, UpToDate: false, Source: "known_av"},
	}
	got = MacAntivirus("5290", &no, &no, known)
	want = []protocol.AntivirusProduct{
		{Name: "XProtect", Enabled: true, UpToDate: false, SignatureVersion: "5290", Source: "xprotect"},
		{Name: "Gatekeeper", Enabled: false, UpToDate: true, Source: "xprotect"},
		known[0], known[1],
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("full:\n got %+v\nwant %+v", got, want)
	}
	// Nothing readable: an empty, non-nil list (never an invented XProtect).
	if got := MacAntivirus("", nil, nil, nil); got == nil || len(got) != 0 {
		t.Errorf("empty: %+v", got)
	}
}

func TestDetectKnownAV(t *testing.T) {
	installed := map[string]bool{
		"/Applications/Falcon.app":       true,
		"/Applications/Malwarebytes.app": true,
	}
	exists := func(p string) bool { return installed[p] }
	// Process names as the kernel reports them: truncated to 15 characters,
	// any case.
	procs := []string{"launchd", "FALCOND", "wdavdaemon", "com.crowdstrike", "sentinelone-age"}

	got := DetectKnownAV(KnownAVDarwin, exists, procs)
	want := []protocol.AntivirusProduct{
		{Name: "CrowdStrike Falcon", Enabled: true, UpToDate: true, Source: "known_av"},
		{Name: "Malwarebytes", Enabled: false, UpToDate: false, Source: "known_av"}, // installed, not running
		{Name: "Microsoft Defender for Endpoint", Enabled: true, UpToDate: true, Source: "known_av"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("darwin:\n got %+v\nwant %+v", got, want)
	}
	// Linux: "sentinelone-agent" is longer than the kernel's 15 characters.
	gotLinux := DetectKnownAV(KnownAVLinux, func(string) bool { return false }, procs)
	wantLinux := []protocol.AntivirusProduct{
		{Name: "CrowdStrike Falcon", Enabled: true, UpToDate: true, Source: "known_av"},
		{Name: "Microsoft Defender for Endpoint", Enabled: true, UpToDate: true, Source: "known_av"},
		{Name: "SentinelOne", Enabled: true, UpToDate: true, Source: "known_av"},
	}
	if !reflect.DeepEqual(gotLinux, wantLinux) {
		t.Errorf("linux:\n got %+v\nwant %+v", gotLinux, wantLinux)
	}
	if got := DetectKnownAV(KnownAVLinux, func(string) bool { return false }, []string{"bash", "sshd"}); len(got) != 0 {
		t.Errorf("no AV: %+v", got)
	}
	if !HasProcess([]string{"systemd", "ClamD"}, "clamd") || HasProcess([]string{"clamdscan"}, "clamd") {
		t.Error("HasProcess")
	}
	// The tables list every product the brief names, each with a detection rule.
	for _, table := range [][]KnownAV{KnownAVDarwin, KnownAVLinux} {
		seen := map[string]bool{}
		for _, k := range table {
			if k.Name == "" || seen[k.Name] || (len(k.Paths) == 0 && len(k.Processes) == 0) {
				t.Errorf("bad table entry %+v", k)
			}
			seen[k.Name] = true
		}
	}
	for _, name := range []string{"CrowdStrike Falcon", "SentinelOne", "Sophos", "Microsoft Defender for Endpoint", "Bitdefender", "ESET", "Malwarebytes", "Jamf Protect", "Trend Micro", "Avast", "AVG", "Norton", "McAfee / Trellix"} {
		found := false
		for _, k := range KnownAVDarwin {
			found = found || k.Name == name
		}
		if !found {
			t.Errorf("macOS table lacks %s", name)
		}
	}
}

func TestClamAV(t *testing.T) {
	version, built, ok := ParseClamAVHeader(fixture(t, "clamav_daily_header.bin"))
	if !ok || version != "27812" || !built.Equal(time.Date(2026, 11, 7, 9, 26, 0, 0, time.UTC)) {
		t.Fatalf("header: %q %v %v", version, built, ok)
	}
	// Older databases have no trailing Unix time: the text date is used.
	version, built, ok = ParseClamAVHeader([]byte("ClamAV-VDB:07 Nov 2026 04-26 -0500:27812:2067589:90:X:X:raynman"))
	if !ok || version != "27812" || !built.Equal(time.Date(2026, 11, 7, 9, 26, 0, 0, time.UTC)) {
		t.Fatalf("old header: %q %v %v", version, built, ok)
	}
	for _, bad := range []string{"", "PK\x03\x04", "ClamAV-VDB:", "ClamAV-VDB:date:notanumber:1"} {
		if _, _, ok := ParseClamAVHeader([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}

	fresh := ClamAVProduct(ClamAV{Installed: true, ClamdRunning: true, Version: "27812", Built: built}, fixedNow)
	if want := (protocol.AntivirusProduct{Name: "ClamAV", Enabled: true, UpToDate: true, SignatureVersion: "27812", Source: "clamav"}); fresh != want {
		t.Errorf("fresh: %+v", fresh)
	}
	// Installed but the daemon is stopped and the database is a month old.
	stale := ClamAVProduct(ClamAV{Installed: true, Version: "27700", Built: fixedNow.Add(-30 * 24 * time.Hour)}, fixedNow)
	if stale.Enabled || stale.UpToDate {
		t.Errorf("stale: %+v", stale)
	}
	// No database at all: never reported as up to date.
	if p := ClamAVProduct(ClamAV{Installed: true, ClamdRunning: true}, fixedNow); p.UpToDate || p.SignatureVersion != "" {
		t.Errorf("no database: %+v", p)
	}
}
