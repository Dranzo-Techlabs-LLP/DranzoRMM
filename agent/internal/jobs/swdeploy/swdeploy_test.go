package swdeploy_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/swdeploy"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
)

var alice = &platform.User{Name: "alice", UID: "501", GID: "20", Home: "/Users/alice"}

func wingetFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "software", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func linuxEnv() swdeploy.Env {
	return swdeploy.Env{OSName: "Linux", Managers: []string{"apt", "dnf"}, Lookup: swtest.Lookup("apt-get", "dpkg-query", "dnf", "rpm")}
}

func windowsEnv() swdeploy.Env {
	return swdeploy.Env{OSName: "Windows", Managers: []string{"winget"}, Lookup: swtest.Lookup("winget")}
}

func macEnv(plat platform.Platform, root bool) swdeploy.Env {
	return swdeploy.Env{OSName: "macOS", Managers: []string{"brew"}, Lookup: swtest.Lookup(),
		Brew: &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return root }}}
}

func run(t *testing.T, h jobs.Handler, plat platform.Platform, spec any) (jobs.Result, *swtest.Job) {
	t.Helper()
	job := swtest.NewJob(context.Background(), plat, t.TempDir(), spec)
	return h.Handle(job.JobContext), job
}

func installResult(t *testing.T, res jobs.Result) protocol.InstallResult {
	t.Helper()
	r, ok := res.Result.(protocol.InstallResult)
	if !ok {
		t.Fatalf("result is %T (%+v), status %s: %s", res.Result, res.Result, res.Status, res.Message)
	}
	return r
}

func TestAptInstallAndRemoveArgv(t *testing.T) {
	installed := false
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		line := c.Line()
		switch {
		case strings.Contains(line, " install -- "):
			installed = true
			return swtest.Reply{Stdout: "Setting up tree (2.1.0-1) ...\n"}
		case strings.Contains(line, " remove -- "):
			installed = false
		case strings.HasSuffix(c.Path, "dpkg-query"):
			if installed {
				return swtest.Reply{Stdout: "ii \t2.1.0-1\n"}
			}
			return swtest.Reply{Stderr: "dpkg-query: no packages found matching tree\n", Exit: 1}
		}
		return swtest.Reply{}
	}}
	plat := rec.Platform(nil)
	res, job := run(t, swdeploy.NewWithEnv(false, linuxEnv()), plat, protocol.SoftwareSpec{Manager: "apt", PackageID: "tree", Version: "2.1.0-1"})
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s: %s", res.Status, res.Message)
	}
	if r := installResult(t, res); !r.Installed || r.Version != "2.1.0-1" {
		t.Fatalf("result = %+v", r)
	}
	want := []string{
		"/fake/bin/apt-get -o DPkg::Lock::Timeout=120 update",
		"/fake/bin/apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=120 install -- tree=2.1.0-1",
		`/fake/bin/dpkg-query -W -f=${db:Status-Abbrev}\t${Version}\n -- tree`,
	}
	if got := rec.Lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, c := range rec.Calls()[:2] {
		if !c.HasEnv("DEBIAN_FRONTEND=noninteractive") || c.AsUser != nil {
			t.Fatalf("apt-get must run non-interactively as the system: %+v", c)
		}
	}
	if !strings.Contains(job.Out.String(), "Setting up tree") {
		t.Fatalf("tool output not streamed: %q", job.Out.String())
	}

	rec2 := &swtest.Recorder{Respond: rec.Respond}
	res, _ = run(t, swdeploy.NewWithEnv(true, linuxEnv()), rec2.Platform(nil), protocol.SoftwareSpec{Manager: "apt", PackageID: "tree"})
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("uninstall status %s: %s", res.Status, res.Message)
	}
	if r := installResult(t, res); r.Installed || r.Version != "" {
		t.Fatalf("uninstall result = %+v", r)
	}
	if got := rec2.Lines()[0]; got != "/fake/bin/apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=120 remove -- tree" {
		t.Fatalf("remove command = %s", got)
	}
}

func TestDnfArgv(t *testing.T) {
	installed := false
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		switch {
		case strings.Contains(c.Line(), "dnf -y install"):
			installed = true
		case strings.Contains(c.Line(), "dnf -y remove"):
			installed = false
		case strings.HasSuffix(c.Path, "rpm"):
			if installed {
				return swtest.Reply{Stdout: "0\t1.8.0\t10.el9\n"}
			}
			return swtest.Reply{Stdout: "package tree is not installed\n", Exit: 1}
		}
		return swtest.Reply{}
	}}
	res, _ := run(t, swdeploy.NewWithEnv(false, linuxEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "dnf", PackageID: "tree", Version: "1.8.0-10.el9"})
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || !r.Installed || r.Version != "1.8.0-10.el9" {
		t.Fatalf("status %s result %+v", res.Status, r)
	}
	res, _ = run(t, swdeploy.NewWithEnv(true, linuxEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "dnf", PackageID: "tree"})
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || r.Installed {
		t.Fatalf("uninstall: status %s result %+v", res.Status, r)
	}
	want := []string{
		"/fake/bin/dnf -y install -- tree-1.8.0-10.el9",
		`/fake/bin/rpm -q --qf %{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n -- tree`,
		"/fake/bin/dnf -y remove -- tree",
		`/fake/bin/rpm -q --qf %{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n -- tree`,
	}
	if got := rec.Lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
}

func TestWingetArgv(t *testing.T) {
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if c.Args[0] == "list" {
			return swtest.Reply{Stdout: wingetFixture(t, "winget_list_exact.txt")}
		}
		return swtest.Reply{Stdout: "Successfully installed\n"}
	}}
	res, _ := run(t, swdeploy.NewWithEnv(false, windowsEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "winget", PackageID: "7zip.7zip", Version: "24.08"})
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || !r.Installed || r.Version != "24.08" {
		t.Fatalf("status %s (%s) result %+v", res.Status, res.Message, r)
	}
	want := []string{
		"/fake/bin/winget install -e --id 7zip.7zip --version 24.08 --silent --accept-package-agreements --accept-source-agreements --disable-interactivity",
		"/fake/bin/winget list -e --id 7zip.7zip --accept-source-agreements --disable-interactivity",
	}
	if got := rec.Lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}

	// Uninstall: the tool says success and the re-query no longer finds it.
	rec = &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if c.Args[0] == "list" {
			return swtest.Reply{Stdout: wingetFixture(t, "winget_list_none.txt"), Exit: -1978335212}
		}
		return swtest.Reply{}
	}}
	res, _ = run(t, swdeploy.NewWithEnv(true, windowsEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "winget", PackageID: "7zip.7zip"})
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || r.Installed {
		t.Fatalf("uninstall: status %s result %+v", res.Status, r)
	}
	if got := rec.Lines()[0]; got != "/fake/bin/winget uninstall -e --id 7zip.7zip --silent --accept-source-agreements --disable-interactivity" {
		t.Fatalf("uninstall command = %s", got)
	}
}

func TestBrewAlwaysRunsAsConsoleUser(t *testing.T) {
	respond := func(c swtest.Call) swtest.Reply {
		if c.Args[0] == "list" {
			return swtest.Reply{Stdout: "wget 1.24.5\n"}
		}
		return swtest.Reply{Stdout: "==> Pouring wget\n"}
	}
	// The agent runs as root, alice is logged in.
	rec := &swtest.Recorder{Respond: respond}
	plat := rec.Platform(alice)
	res, _ := run(t, swdeploy.NewWithEnv(false, macEnv(plat, true)), plat, protocol.SoftwareSpec{Manager: "brew", PackageID: "wget"})
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || !r.Installed || r.Version != "1.24.5" {
		t.Fatalf("status %s (%s) result %+v", res.Status, res.Message, r)
	}
	want := []string{
		"/opt/homebrew/bin/brew install -- wget",
		"/opt/homebrew/bin/brew list --versions -- wget",
	}
	if got := rec.Lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	for _, c := range rec.Calls() {
		if c.AsUser == nil || c.AsUser.UID != "501" {
			t.Fatalf("brew ran as root: %+v", c)
		}
		if !c.HasEnv("NONINTERACTIVE=1") {
			t.Fatalf("brew must not prompt: %v", c.Env)
		}
	}
	if plat.RanAsUser != 2 {
		t.Fatalf("RanAsUser = %d", plat.RanAsUser)
	}

	// Nobody logged in: clear failure, brew is never started.
	rec = &swtest.Recorder{Respond: respond}
	plat = rec.Platform(nil)
	res, _ = run(t, swdeploy.NewWithEnv(false, macEnv(plat, true)), plat, protocol.SoftwareSpec{Manager: "brew", PackageID: "wget"})
	if res.Status != protocol.StatusFailed || res.Message != "no logged-in user" {
		t.Fatalf("status %s: %q", res.Status, res.Message)
	}
	if len(rec.Calls()) != 0 {
		t.Fatalf("brew was started without a user: %v", rec.Lines())
	}

	// A version cannot be chosen with Homebrew.
	rec = &swtest.Recorder{Respond: respond}
	plat = rec.Platform(alice)
	res, _ = run(t, swdeploy.NewWithEnv(false, macEnv(plat, true)), plat, protocol.SoftwareSpec{Manager: "brew", PackageID: "node", Version: "20.1.0"})
	if res.Status != protocol.StatusRejected || len(rec.Calls()) != 0 {
		t.Fatalf("status %s: %s (%v)", res.Status, res.Message, rec.Lines())
	}

	// Uninstall.
	rec = &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if c.Args[0] == "list" {
			return swtest.Reply{Stderr: "Error: No such keg\n", Exit: 1}
		}
		return swtest.Reply{}
	}}
	plat = rec.Platform(alice)
	res, _ = run(t, swdeploy.NewWithEnv(true, macEnv(plat, true)), plat, protocol.SoftwareSpec{Manager: "brew", PackageID: "wget"})
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || r.Installed {
		t.Fatalf("uninstall: %s %+v", res.Status, r)
	}
	if got := rec.Lines()[0]; got != "/opt/homebrew/bin/brew uninstall -- wget" || rec.Calls()[0].AsUser == nil {
		t.Fatalf("uninstall command = %s", got)
	}
}

func TestInjectionAttemptsAreRejected(t *testing.T) {
	bad := []string{
		"x; rm -rf /",
		"-o Foo",
		"-oFoo",
		"--allow-unauthenticated",
		"$(id)",
		"`id`",
		"a b",
		"a|b",
		"a&b",
		"a>b",
		"a\nb",
		"a\x00b",
		"../../etc/passwd\n",
		"",
		" tree",
		"tree'",
		`tree"`,
		"tree=1.0", // "=" would smuggle a version into the id
		strings.Repeat("a", 201),
	}
	for _, uninstall := range []bool{false, true} {
		for _, manager := range []string{"apt", "dnf", "winget", "brew"} {
			for _, id := range bad {
				rec := &swtest.Recorder{}
				plat := rec.Platform(alice)
				env := swdeploy.Env{OSName: "Test", Managers: []string{"apt", "dnf", "winget", "brew"},
					Lookup: swtest.Lookup("apt-get", "dpkg-query", "dnf", "rpm", "winget"),
					Brew:   &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return true }}}
				res, _ := run(t, swdeploy.NewWithEnv(uninstall, env), plat, protocol.SoftwareSpec{Manager: manager, PackageID: id})
				if res.Status != protocol.StatusRejected {
					t.Errorf("%s packageId %q: status %s", manager, id, res.Status)
				}
				if n := len(rec.Calls()); n != 0 {
					t.Errorf("%s packageId %q: %d commands were run: %v", manager, id, n, rec.Lines())
				}
				// The same strings as a version.
				if id == "" {
					continue
				}
				res, _ = run(t, swdeploy.NewWithEnv(uninstall, env), plat, protocol.SoftwareSpec{Manager: manager, PackageID: "tree", Version: id})
				if res.Status != protocol.StatusRejected || len(rec.Calls()) != 0 {
					t.Errorf("%s version %q: status %s, commands %v", manager, id, res.Status, rec.Lines())
				}
			}
		}
	}
	// Unknown manager, wrong JSON types.
	rec := &swtest.Recorder{}
	for _, spec := range []string{
		`{"manager":"pip","packageId":"tree"}`,
		`{"manager":"","packageId":"tree"}`,
		`{"manager":"apt","packageId":["tree"]}`,
		`{"manager":"apt","packageId":42}`,
		`{"manager":"apt"}`,
		`{}`,
	} {
		res, _ := run(t, swdeploy.NewWithEnv(false, linuxEnv()), rec.Platform(nil), spec)
		if res.Status != protocol.StatusRejected {
			t.Errorf("spec %s: status %s", spec, res.Status)
		}
	}
	if len(rec.Calls()) != 0 {
		t.Fatalf("commands were run: %v", rec.Lines())
	}
	for _, good := range []string{"tree", "7zip.7zip", "libstdc++6", "python3.11", "node@20", "homebrew/cask/firefox", "libc6:arm64", "Microsoft.VCRedist.2015+.x64", "perl-Data_Dumper"} {
		if !swdeploy.ValidID(good) {
			t.Errorf("valid id %q refused", good)
		}
	}
}

// The protocol's packageId pattern also matches URLs and paths. dnf, apt and
// Homebrew would install such an argument as a FILE, bypassing the
// repositories' signatures; every manager therefore only accepts names.
func TestURLsAndPathsAreNotPackageNames(t *testing.T) {
	cases := map[string][]string{
		"dnf":    {"https://evil.example/x.rpm", "http://evil.example/x.rpm", "tmp/x.rpm", "x.rpm", "a/b", "name:1", "pkg@group"},
		"apt":    {"https://evil.example/x.deb", "tmp/x.deb", "a/b", "Tree", "pkg_name", "pkg@x"},
		"brew":   {"https://evil.example/x.rb", "tmp/x.rb", "x.rb", "a/../b", "a//b", "a/b/c/d", "tap/", "user:pass"},
		"winget": {"https://evil.example/x", "a/b", "a:b", "a@b"},
	}
	for manager, ids := range cases {
		for _, id := range ids {
			if !protocol.ValidPackageID(id) {
				t.Fatalf("test case %q does not even match the protocol pattern", id)
			}
			for _, uninstall := range []bool{false, true} {
				rec := &swtest.Recorder{}
				plat := rec.Platform(alice)
				env := swdeploy.Env{OSName: "Test", Managers: []string{"apt", "dnf", "winget", "brew"},
					Lookup: swtest.Lookup("apt-get", "dpkg-query", "dnf", "rpm", "winget"),
					Brew:   &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return true }}}
				res, _ := run(t, swdeploy.NewWithEnv(uninstall, env), plat, protocol.SoftwareSpec{Manager: manager, PackageID: id})
				if res.Status != protocol.StatusRejected || len(rec.Calls()) != 0 {
					t.Errorf("%s %q: status %s, commands %v", manager, id, res.Status, rec.Lines())
				}
			}
		}
	}
	// A version must not turn a name into a path or URL either.
	rec := &swtest.Recorder{}
	for _, v := range []string{"x://evil.example/a.rpm", "1/2", "1@2"} {
		res, _ := run(t, swdeploy.NewWithEnv(false, linuxEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "dnf", PackageID: "http", Version: v})
		if res.Status != protocol.StatusRejected || len(rec.Calls()) != 0 {
			t.Errorf("version %q: status %s, commands %v", v, res.Status, rec.Lines())
		}
	}
	// What must keep working.
	good := map[string][]string{
		"apt":    {"tree", "libstdc++6", "python3.11", "libc6:arm64"},
		"dnf":    {"tree", "bash.x86_64", "perl-Data_Dumper", "libstdc++"},
		"brew":   {"wget", "node@20", "homebrew/cask/firefox", "user/tap/formula"},
		"winget": {"7zip.7zip", "Microsoft.VCRedist.2015+.x64", "9NBLGGH4NNS1"},
	}
	for manager, ids := range good {
		for _, id := range ids {
			spec := protocol.SoftwareSpec{Manager: manager, PackageID: id}
			if err := swdeploy.Validate(&spec); err != nil {
				t.Errorf("%s %q refused: %v", manager, id, err)
			}
		}
	}
	spec := protocol.SoftwareSpec{Manager: "dnf", PackageID: "openssl", Version: "1:3.0.7-25.el9_3"}
	if err := swdeploy.Validate(&spec); err != nil {
		t.Errorf("epoch version refused: %v", err)
	}
}

func TestWrongManagerForOSIsUnsupported(t *testing.T) {
	rec := &swtest.Recorder{}
	plat := rec.Platform(alice)
	cases := []struct {
		env     swdeploy.Env
		manager string
	}{
		{linuxEnv(), "winget"},
		{linuxEnv(), "brew"},
		{windowsEnv(), "apt"},
		{windowsEnv(), "brew"},
		{macEnv(plat, true), "dnf"},
		{macEnv(plat, true), "winget"},
	}
	for _, c := range cases {
		res, _ := run(t, swdeploy.NewWithEnv(false, c.env), plat, protocol.SoftwareSpec{Manager: c.manager, PackageID: "tree"})
		if res.Status != protocol.StatusUnsupported || !strings.HasPrefix(res.Message, "not supported on this OS: ") || !strings.Contains(res.Message, c.env.OSName) {
			t.Errorf("%s on %s: status %s, message %q", c.manager, c.env.OSName, res.Status, res.Message)
		}
	}
	// The right manager for the OS family, but the tool is absent (dnf on Debian).
	env := swdeploy.Env{OSName: "Linux", Managers: []string{"apt", "dnf"}, Lookup: swtest.Lookup("apt-get", "dpkg-query")}
	res, _ := run(t, swdeploy.NewWithEnv(false, env), plat, protocol.SoftwareSpec{Manager: "dnf", PackageID: "tree"})
	if res.Status != protocol.StatusUnsupported || !strings.Contains(res.Message, "dnf is not installed") {
		t.Fatalf("status %s, message %q", res.Status, res.Message)
	}
	// winget missing for the service account.
	env = swdeploy.Env{OSName: "Windows", Managers: []string{"winget"}, Lookup: swtest.Lookup()}
	res, _ = run(t, swdeploy.NewWithEnv(false, env), plat, protocol.SoftwareSpec{Manager: "winget", PackageID: "7zip.7zip"})
	if res.Status != protocol.StatusUnsupported {
		t.Fatalf("status %s, message %q", res.Status, res.Message)
	}
	if len(rec.Calls()) != 0 {
		t.Fatalf("commands were run: %v", rec.Lines())
	}
}

func TestResultComesFromTheReQuery(t *testing.T) {
	// The tool fails: failed, and the query says the package is not there.
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if strings.Contains(c.Line(), " install -- ") {
			return swtest.Reply{Stderr: "E: Unable to locate package nosuchpkg\n", Exit: 100}
		}
		if strings.HasSuffix(c.Path, "dpkg-query") {
			return swtest.Reply{Exit: 1}
		}
		return swtest.Reply{}
	}}
	res, job := run(t, swdeploy.NewWithEnv(false, linuxEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "apt", PackageID: "nosuchpkg"})
	if r := installResult(t, res); res.Status != protocol.StatusFailed || r.Installed || res.ExitCode == nil || *res.ExitCode != 100 {
		t.Fatalf("status %s result %+v exit %v", res.Status, r, res.ExitCode)
	}
	if !strings.Contains(res.Message, "apt-get exited with code 100") || !strings.Contains(job.ErrOut.String(), "Unable to locate package") {
		t.Fatalf("message %q, stderr %q", res.Message, job.ErrOut.String())
	}
	// The tool claims success but the package is not installed: failed.
	rec = &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "dpkg-query") {
			return swtest.Reply{Exit: 1}
		}
		return swtest.Reply{}
	}}
	res, _ = run(t, swdeploy.NewWithEnv(false, linuxEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "apt", PackageID: "tree"})
	if r := installResult(t, res); res.Status != protocol.StatusFailed || r.Installed {
		t.Fatalf("status %s result %+v", res.Status, r)
	}
	// A failing index refresh alone does not fail the installation.
	rec = &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Line(), " update") {
			return swtest.Reply{Exit: 100}
		}
		if strings.HasSuffix(c.Path, "dpkg-query") {
			return swtest.Reply{Stdout: "ii \t1.0\n"}
		}
		return swtest.Reply{}
	}}
	res, _ = run(t, swdeploy.NewWithEnv(false, linuxEnv()), rec.Platform(nil), protocol.SoftwareSpec{Manager: "apt", PackageID: "tree"})
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s: %s", res.Status, res.Message)
	}
	// Cancellation stops before the next command.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec = &swtest.Recorder{}
	job = swtest.NewJob(ctx, rec.Platform(nil), t.TempDir(), protocol.SoftwareSpec{Manager: "dnf", PackageID: "tree"})
	res = swdeploy.NewWithEnv(false, linuxEnv()).Handle(job.JobContext)
	if res.Status != protocol.StatusFailed || len(rec.Calls()) != 1 {
		t.Fatalf("cancelled: status %s, commands %v", res.Status, rec.Lines())
	}
}
