package software_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNormalizeSortDedupeCap(t *testing.T) {
	raw := []protocol.SoftwareItem{
		{Name: "zeta", Version: "1", Source: "dpkg", ID: "zeta"},
		{Name: "Alpha", Version: "2", Source: "dpkg", ID: "alpha"},
		{Name: "alpha", Version: "1", Source: "rpm", ID: "alpha"},
		{Name: "Alpha", Version: "2", Source: "dpkg", ID: "ALPHA"}, // duplicate (ids compare case-insensitively)
		{Name: "", Version: "1", Source: "dpkg", ID: "noname"},     // dropped
		{Name: "nosource", Version: "1"},                           // dropped
		{Name: "NoID", Version: "1", Source: "app"},
		{Name: "noid", Version: "1", Source: "app"}, // duplicate by name
	}
	items, truncated := software.Normalize(raw)
	if truncated {
		t.Fatal("unexpected truncation")
	}
	var got []string
	for _, it := range items {
		got = append(got, it.Name+"/"+it.Version+"/"+it.Source)
	}
	want := "Alpha/2/dpkg alpha/1/rpm NoID/1/app zeta/1/dpkg"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
	// Stable: the same input in another order gives the same output.
	rev := make([]protocol.SoftwareItem, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		rev = append(rev, raw[i])
	}
	again, _ := software.Normalize(rev)
	if len(again) != len(items) {
		t.Fatalf("order-dependent result: %d vs %d", len(again), len(items))
	}
	for i := range items {
		if !strings.EqualFold(items[i].Name, again[i].Name) || items[i].Version != again[i].Version || items[i].Source != again[i].Source {
			t.Fatalf("position %d differs: %+v vs %+v", i, items[i], again[i])
		}
	}

	// Cap at 5,000 items.
	big := make([]protocol.SoftwareItem, 0, 6000)
	for i := 0; i < 6000; i++ {
		big = append(big, protocol.SoftwareItem{Name: fmt.Sprintf("pkg-%05d", i), Version: "1.0", Source: "dpkg", ID: fmt.Sprintf("pkg-%05d", i)})
	}
	items, truncated = software.Normalize(big)
	if len(items) != protocol.MaxSoftwareItems || !truncated {
		t.Fatalf("cap: %d items, truncated=%v", len(items), truncated)
	}
	if items[0].Name != "pkg-00000" || items[4999].Name != "pkg-04999" {
		t.Fatalf("cap kept the wrong items: %s .. %s", items[0].Name, items[4999].Name)
	}

	// Oversized fields are cut and the payload stays below the message limit.
	huge := make([]protocol.SoftwareItem, 0, 5000)
	for i := 0; i < 5000; i++ {
		huge = append(huge, protocol.SoftwareItem{
			Name: fmt.Sprintf("%05d-%s", i, strings.Repeat("n", 1000)), Version: strings.Repeat("v", 1000),
			Publisher: strings.Repeat("p", 1000), Source: "registry", ID: fmt.Sprintf("%05d-%s", i, strings.Repeat("i", 1000)),
		})
	}
	items, truncated = software.Normalize(huge)
	if !truncated || len(items) == 0 || len(items) >= 5000 {
		t.Fatalf("size budget: %d items, truncated=%v", len(items), truncated)
	}
	total := 0
	for _, it := range items {
		if len(it.Name) > 256 || len(it.Version) > 128 || len(it.Publisher) > 256 || len(it.ID) > 256 {
			t.Fatalf("field not capped: %d %d %d %d", len(it.Name), len(it.Version), len(it.Publisher), len(it.ID))
		}
		total += len(it.Name) + len(it.Version) + len(it.Publisher) + len(it.ID) + 96
	}
	if total > 2<<20 {
		t.Fatalf("payload estimate %d exceeds the 2 MiB message limit", total)
	}
}

func TestCollectorReportShape(t *testing.T) {
	c := software.NewCollectorWith(&platform.Fake{}, func(context.Context, platform.Platform) ([]protocol.SoftwareItem, []string) {
		return []protocol.SoftwareItem{{Name: "b", Version: "1", Source: "dpkg", ID: "b"}, {Name: "a", Version: "1", Source: "dpkg", ID: "a"}}, []string{"snap", "flatpak"}
	})
	inv := c.Collect(context.Background())
	if len(inv.Items) != 2 || inv.Items[0].Name != "a" || inv.Truncated {
		t.Fatalf("items = %+v", inv.Items)
	}
	if strings.Join(inv.Unsupported, ",") != "flatpak,snap" {
		t.Fatalf("unsupported = %v", inv.Unsupported)
	}
	if inv.CollectedAt.IsZero() || inv.CollectedAt.Location() != time.UTC {
		t.Fatalf("collectedAt = %v", inv.CollectedAt)
	}
	// Nothing collected still yields non-null arrays.
	empty := software.NewCollectorWith(&platform.Fake{}, func(context.Context, platform.Platform) ([]protocol.SoftwareItem, []string) { return nil, nil }).Collect(context.Background())
	if empty.Items == nil || empty.Unsupported == nil {
		t.Fatalf("null arrays in report: %+v", empty)
	}
}

func TestGatherLinux(t *testing.T) {
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		switch {
		case strings.HasSuffix(c.Path, "dpkg-query"):
			return swtest.Reply{Stdout: fixture(t, "dpkg_query_debian12.txt")}
		case strings.HasSuffix(c.Path, "snap"):
			return swtest.Reply{Stdout: fixture(t, "snap_list.txt")}
		case strings.HasSuffix(c.Path, "flatpak"):
			return swtest.Reply{Exit: 1, Stderr: "error: Unable to connect to system bus"}
		}
		return swtest.Reply{Exit: 127}
	}}
	items, unsupported := software.GatherLinux(context.Background(), rec.Platform(nil), swtest.Lookup("dpkg-query", "snap", "flatpak"))
	if len(items) < 85 {
		t.Fatalf("items = %d", len(items))
	}
	if strings.Join(unsupported, ",") != "flatpak" {
		t.Fatalf("unsupported = %v", unsupported)
	}
	lines := rec.Lines()
	want := []string{
		"/fake/bin/dpkg-query -W -f=" + software.DpkgQueryFormat,
		"/fake/bin/snap list",
		"/fake/bin/flatpak list --app --columns=name,application,version",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	for _, c := range rec.Calls() {
		if !c.HasEnv("LC_ALL=C") || c.AsUser != nil {
			t.Fatalf("command not run with the C locale as the system: %+v", c)
		}
	}

	// rpm-based system.
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply { return swtest.Reply{Stdout: fixture(t, "rpm_qa_rocky9.txt")} }}
	items, unsupported = software.GatherLinux(context.Background(), rec.Platform(nil), swtest.Lookup("rpm"))
	if len(items) < 130 || len(unsupported) != 0 {
		t.Fatalf("rpm: %d items, unsupported %v", len(items), unsupported)
	}
	if got := rec.Lines(); len(got) != 1 || got[0] != "/fake/bin/rpm -qa --qf "+software.RpmQueryFormat {
		t.Fatalf("rpm command = %v", got)
	}

	// Neither package database: both are reported as unsupported, nothing fails.
	rec = &swtest.Recorder{}
	items, unsupported = software.GatherLinux(context.Background(), rec.Platform(nil), swtest.Lookup())
	if len(items) != 0 || strings.Join(unsupported, ",") != "dpkg,rpm" || len(rec.Calls()) != 0 {
		t.Fatalf("empty system: %v %v %v", items, unsupported, rec.Lines())
	}
}

var alice = &platform.User{Name: "alice", UID: "501", GID: "20", Home: "/Users/alice"}

func TestGatherDarwinWithFakes(t *testing.T) {
	apps := t.TempDir()
	mk := func(rel, plist string) {
		dir := filepath.Join(apps, rel, "Contents")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if plist != "" {
			if err := os.WriteFile(filepath.Join(dir, "Info.plist"), []byte(plist), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("Calculator.app", fixture(t, "Info_calculator.plist"))
	mk("Utilities/Binary.app", "bplist00 binary content")
	mk("Broken.app", "")
	mk("Vendor/Deep/TooDeep.app", fixture(t, "Info_calculator.plist"))
	mk(".Hidden.app", fixture(t, "Info_calculator.plist"))

	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		line := c.Line()
		switch {
		case strings.Contains(line, "plutil -convert xml1 -o -"):
			return swtest.Reply{Stdout: `<plist version="1.0"><dict><key>CFBundleName</key><string>BinaryApp</string><key>CFBundleShortVersionString</key><string>3.2.1</string><key>CFBundleIdentifier</key><string>com.example.binary</string></dict></plist>`}
		case strings.HasSuffix(line, "pkgutil --pkgs"):
			return swtest.Reply{Stdout: fixture(t, "pkgutil_pkgs.txt")}
		case strings.Contains(line, "pkgutil --pkg-info"):
			return swtest.Reply{Stdout: fixture(t, "pkgutil_info.txt")}
		case strings.Contains(line, "brew list --formula"):
			return swtest.Reply{Stdout: "wget 1.24.5\njq 1.7.1\n"}
		case strings.Contains(line, "brew list --cask"):
			return swtest.Reply{Stdout: "firefox 131.0\n"}
		}
		return swtest.Reply{Exit: 1}
	}}
	plat := rec.Platform(alice)
	brew := &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return true }}
	items, unsupported := software.GatherDarwin(context.Background(), plat, swtest.Lookup("plutil", "pkgutil"), brew, []string{apps})
	if len(unsupported) != 0 {
		t.Fatalf("unsupported = %v", unsupported)
	}
	bySource := map[string][]string{}
	for _, it := range items {
		bySource[it.Source] = append(bySource[it.Source], it.Name+"@"+it.Version)
	}
	if got := strings.Join(bySource["app"], ","); got != "Broken@,Calculator@"+appVersion(t)+",BinaryApp@3.2.1" {
		t.Fatalf("apps = %s", got)
	}
	if len(bySource["pkgutil"]) != 12 || len(bySource["brew"]) != 3 {
		t.Fatalf("pkgutil %d, brew %d", len(bySource["pkgutil"]), len(bySource["brew"]))
	}
	// Homebrew ran as the console user, everything else as the system.
	brewCalls := 0
	for _, c := range rec.Calls() {
		if strings.HasSuffix(c.Path, "brew") {
			brewCalls++
			if c.AsUser == nil || c.AsUser.Name != "alice" {
				t.Fatalf("brew ran as root: %+v", c)
			}
			if !c.HasEnv("HOMEBREW_NO_AUTO_UPDATE=1") || !c.HasEnv("NONINTERACTIVE=1") {
				t.Fatalf("brew environment incomplete: %v", c.Env)
			}
		} else if c.AsUser != nil {
			t.Fatalf("system tool ran as the user: %+v", c)
		}
	}
	if brewCalls != 2 {
		t.Fatalf("brew calls = %d", brewCalls)
	}

	// Nobody logged in: brew is not run at all (never as root) and is reported unsupported.
	rec2 := &swtest.Recorder{Respond: rec.Respond}
	plat2 := rec2.Platform(nil)
	brew2 := &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat2, IsRoot: func() bool { return true }}
	_, unsupported = software.GatherDarwin(context.Background(), plat2, swtest.Lookup("plutil", "pkgutil"), brew2, []string{apps})
	if strings.Join(unsupported, ",") != "brew" {
		t.Fatalf("unsupported = %v", unsupported)
	}
	for _, c := range rec2.Calls() {
		if strings.HasSuffix(c.Path, "brew") {
			t.Fatalf("brew was run although nobody is logged in: %+v", c)
		}
	}

	// Homebrew not installed: silently nothing.
	rec3 := &swtest.Recorder{Respond: rec.Respond}
	plat3 := rec3.Platform(alice)
	_, unsupported = software.GatherDarwin(context.Background(), plat3, swtest.Lookup("plutil", "pkgutil"), &software.Brew{Plat: plat3, IsRoot: func() bool { return true }}, []string{apps})
	if len(unsupported) != 0 {
		t.Fatalf("unsupported = %v", unsupported)
	}
}

func appVersion(t *testing.T) string {
	t.Helper()
	plist, err := software.ParseInfoPlistXML([]byte(fixture(t, "Info_calculator.plist")))
	if err != nil {
		t.Fatal(err)
	}
	return plist["CFBundleShortVersionString"]
}

func TestBrewNeverRunsAsRoot(t *testing.T) {
	ctx := context.Background()
	rec := &swtest.Recorder{}
	root := func() bool { return true }

	// Root with a console user: runs in that user's session.
	b := &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: rec.Platform(alice), IsRoot: root}
	cmd, err := b.Command(ctx, true, "install", "--", "wget")
	if err != nil || cmd.AsUser == nil || cmd.AsUser.UID != "501" || cmd.Dir != "/Users/alice" {
		t.Fatalf("cmd = %+v, err = %v", cmd, err)
	}
	// Root and nobody logged in: refused.
	b = &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: rec.Platform(nil), IsRoot: root}
	if _, err := b.Command(ctx, true, "install", "--", "wget"); !errors.Is(err, platform.ErrNoConsoleUser) {
		t.Fatalf("err = %v", err)
	}
	// The "console user" being root itself is no better.
	for _, u := range []*platform.User{{Name: "root", UID: "0"}, {Name: "weird", UID: "0"}, {Name: "root", UID: "501"}} {
		b = &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: rec.Platform(u), IsRoot: root}
		if _, err := b.Command(ctx, true, "list"); !errors.Is(err, platform.ErrNoConsoleUser) {
			t.Fatalf("user %+v: err = %v", u, err)
		}
	}
	// IsRoot unknown is treated as root.
	b = &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: rec.Platform(nil)}
	if _, err := b.Command(ctx, true, "list"); !errors.Is(err, platform.ErrNoConsoleUser) {
		t.Fatalf("nil IsRoot: err = %v", err)
	}
	// An unprivileged agent (development) runs brew as itself.
	b = &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: rec.Platform(nil), IsRoot: func() bool { return false }}
	cmd, err = b.Command(ctx, false, "list")
	if err != nil || cmd.AsUser != nil {
		t.Fatalf("unprivileged: %+v %v", cmd, err)
	}
	// Not installed.
	b = &software.Brew{Plat: rec.Platform(alice), IsRoot: root}
	if _, err := b.Command(ctx, false, "list"); !errors.Is(err, software.ErrToolMissing) {
		t.Fatalf("missing brew: err = %v", err)
	}
	if len(rec.Calls()) != 0 {
		t.Fatalf("Command must not run anything: %v", rec.Lines())
	}
}

func TestGatherWinget(t *testing.T) {
	ctx := context.Background()
	rec := &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply { return swtest.Reply{Stdout: fixture(t, "winget_list.txt")} }}
	items, ok := software.GatherWinget(ctx, rec.Platform(nil), `C:\fake\winget.exe`)
	if !ok || len(items) != 8 {
		t.Fatalf("items = %d ok=%v", len(items), ok)
	}
	if got := rec.Lines(); len(got) != 1 || got[0] != `C:\fake\winget.exe list --accept-source-agreements --disable-interactivity` {
		t.Fatalf("command = %v", got)
	}
	// Unusable for the service account: reported, not fatal.
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply {
		return swtest.Reply{Stdout: fixture(t, "winget_list_error.txt"), Exit: -1978335217}
	}}
	if _, ok := software.GatherWinget(ctx, rec.Platform(nil), `C:\fake\winget.exe`); ok {
		t.Fatal("failing winget reported as usable")
	}
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply { return swtest.Reply{Stdout: fixture(t, "winget_list_error.txt")} }}
	if _, ok := software.GatherWinget(ctx, rec.Platform(nil), `C:\fake\winget.exe`); ok {
		t.Fatal("winget without a table reported as usable")
	}
	if _, ok := software.GatherWinget(ctx, rec.Platform(nil), ""); ok {
		t.Fatal("missing winget reported as usable")
	}
}

func TestQueries(t *testing.T) {
	ctx := context.Background()
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		switch {
		case strings.HasSuffix(c.Path, "dpkg-query"):
			return swtest.Reply{Stdout: "ii \t1.8.1-1\n"}
		case strings.HasSuffix(c.Path, "rpm"):
			return swtest.Reply{Stdout: "package tree is not installed\n", Exit: 1}
		case strings.HasSuffix(c.Path, "pkgutil"):
			return swtest.Reply{Stdout: fixture(t, "pkgutil_info.txt")}
		case strings.HasSuffix(c.Path, "winget"):
			return swtest.Reply{Stdout: fixture(t, "winget_list_exact.txt")}
		}
		return swtest.Reply{}
	}}
	plat := rec.Platform(nil)
	if s, err := software.QueryDpkg(ctx, plat, "/usr/bin/dpkg-query", "tree"); err != nil || !s.Installed || s.Version != "1.8.1-1" {
		t.Fatalf("dpkg: %+v %v", s, err)
	}
	if s, err := software.QueryRpm(ctx, plat, "/usr/bin/rpm", "tree"); err != nil || s.Installed {
		t.Fatalf("rpm: %+v %v", s, err)
	}
	if s, err := software.QueryPkgutil(ctx, plat, "/usr/sbin/pkgutil", "com.apple.pkg.CLTools_SDK_macOS13"); err != nil || !s.Installed || s.Version != "26.6.0.0.1781586384" {
		t.Fatalf("pkgutil: %+v %v", s, err)
	}
	if s, err := software.QueryWinget(ctx, plat, "/fake/winget", "7zip.7zip"); err != nil || !s.Installed || s.Version != "24.08" {
		t.Fatalf("winget: %+v %v", s, err)
	}
	want := []string{
		`/usr/bin/dpkg-query -W -f=${db:Status-Abbrev}\t${Version}\n -- tree`,
		`/usr/bin/rpm -q --qf %{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n -- tree`,
		`/usr/sbin/pkgutil --pkg-info com.apple.pkg.CLTools_SDK_macOS13`,
		`/fake/winget list -e --id 7zip.7zip --accept-source-agreements --disable-interactivity`,
	}
	if got := rec.Lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	if _, err := software.QueryDpkg(ctx, plat, "", "tree"); !errors.Is(err, software.ErrToolMissing) {
		t.Fatalf("missing tool: %v", err)
	}
}

func TestOutputBoundsAndTimeout(t *testing.T) {
	rec := &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply {
		return swtest.Reply{Stdout: strings.Repeat("x", software.MaxToolStdout+1000), Stderr: strings.Repeat("e", software.MaxToolStderr+1000), Exit: 3}
	}}
	res, err := software.Output(context.Background(), rec.Platform(nil), time.Second, platform.Command{Path: "/bin/tool"})
	if err != nil || res.ExitCode != 3 || len(res.Stdout) != software.MaxToolStdout || len(res.Stderr) != software.MaxToolStderr {
		t.Fatalf("res: exit %d, %d/%d bytes, err %v", res.ExitCode, len(res.Stdout), len(res.Stderr), err)
	}
	tail := software.NewTail(nil, 5)
	_, _ = tail.Write([]byte("hello "))
	_, _ = tail.Write([]byte("world"))
	if tail.String() != "world" {
		t.Fatalf("tail = %q", tail.String())
	}
}
