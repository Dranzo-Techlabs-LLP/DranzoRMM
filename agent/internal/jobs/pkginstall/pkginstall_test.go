package pkginstall_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/pkginstall"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

const blobID = "11111111-2222-4333-8444-555555555555"

var (
	alice   = &platform.User{Name: "alice", UID: "501", GID: "20", Home: "/Users/alice"}
	content = []byte("this is the installer package content")
)

func windowsEnv() pkginstall.Env {
	return pkginstall.Env{
		OSName: "Windows", Types: []string{"msi", "exe"},
		Detections:     []string{"file", "registry", "winget"},
		UninstallTools: []string{"msiexec", "winget"},
		Lookup:         swtest.Lookup("msiexec", "winget"),
	}
}

func macEnv(plat platform.Platform, appDir string) pkginstall.Env {
	return pkginstall.Env{
		OSName: "macOS", Types: []string{"pkg", "dmg"},
		Detections:     []string{"file", "pkgutil", "brew", "app"},
		UninstallTools: []string{"pkgutil", "brew"},
		Lookup:         swtest.Lookup("installer", "hdiutil", "ditto", "pkgutil", "plutil"),
		Brew:           &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return true }},
		AppDirs:        []string{appDir},
	}
}

func linuxEnv(tools ...string) pkginstall.Env {
	if tools == nil {
		tools = []string{"apt-get", "dpkg", "dpkg-query", "dnf", "rpm"}
	}
	return pkginstall.Env{
		OSName: "Linux", Types: []string{"deb", "rpm"},
		Detections:     []string{"file", "dpkg", "rpm"},
		UninstallTools: []string{"apt-get", "dpkg", "dnf", "rpm", "snap", "flatpak"},
		Lookup:         swtest.Lookup(tools...),
	}
}

func spec(typ, fileName string, args ...string) protocol.PackageInstallSpec {
	return protocol.PackageInstallSpec{
		BlobID: blobID, SHA256: swtest.SHA256(content), SizeBytes: int64(len(content)),
		FileName: fileName, Type: typ, InstallArgs: args,
	}
}

type harness struct {
	rec   *swtest.Recorder
	plat  *platform.Fake
	blobs *swtest.Blobs
	temp  string
}

func newHarness(t *testing.T, user *platform.User, respond func(c swtest.Call) swtest.Reply) *harness {
	rec := &swtest.Recorder{Respond: respond}
	return &harness{rec: rec, plat: rec.Platform(user), blobs: &swtest.Blobs{Content: content}, temp: t.TempDir()}
}

func (h *harness) run(handler jobs.Handler, spec any) (jobs.Result, *swtest.Job) {
	job := swtest.NewJob(context.Background(), h.plat, h.temp, spec)
	job.Blobs = h.blobs
	return handler.Handle(job.JobContext), job
}

// leftovers lists what is left in the job temp directory.
func (h *harness) leftovers(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(h.temp)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func installResult(t *testing.T, res jobs.Result) protocol.InstallResult {
	t.Helper()
	r, ok := res.Result.(protocol.InstallResult)
	if !ok {
		t.Fatalf("result is %T, status %s: %s", res.Result, res.Status, res.Message)
	}
	return r
}

func TestValidFileName(t *testing.T) {
	good := []string{"setup.msi", "Tool 2.1 (x64).exe", "paket-für-büro.pkg", "a", "x.tar.gz", "My App_v1+2@3.dmg"}
	bad := []string{
		"", ".", "..", ".hidden", "../evil.msi", "..\\evil.msi", "dir/evil.msi", `dir\evil.msi`, "/abs.msi", `C:\x.msi`,
		"C:x.msi", "file.msi:stream", "-rf", "--version", "a\x00b", "a\nb", "tab\there", " lead.msi", "trail.msi ", "trail.",
		"wild*.msi", "what?.msi", `quo"te.msi`, "pi|pe.msi", "lt<.msi", "gt>.msi",
		"CON", "con.msi", "NUL", "nul.txt", "COM1", "lpt9.exe", "AUX.pkg", "PRN",
		strings.Repeat("a", 201),
	}
	for _, n := range good {
		if !pkginstall.ValidFileName(n) {
			t.Errorf("valid name %q refused", n)
		}
	}
	for _, n := range bad {
		if pkginstall.ValidFileName(n) {
			t.Errorf("unsafe name %q accepted", n)
		}
	}
}

func TestValidateInstallRejectsBadSpecs(t *testing.T) {
	ok := spec("msi", "setup.msi", "ALLUSERS=1")
	if err := pkginstall.ValidateInstall(&ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*protocol.PackageInstallSpec){
		"blob id":         func(s *protocol.PackageInstallSpec) { s.BlobID = "../../etc/passwd" },
		"blob id upper":   func(s *protocol.PackageInstallSpec) { s.BlobID = "AAAAAAAA-2222-4333-8444-555555555555" },
		"sha short":       func(s *protocol.PackageInstallSpec) { s.SHA256 = "abc" },
		"sha upper":       func(s *protocol.PackageInstallSpec) { s.SHA256 = strings.ToUpper(s.SHA256) },
		"size zero":       func(s *protocol.PackageInstallSpec) { s.SizeBytes = 0 },
		"size negative":   func(s *protocol.PackageInstallSpec) { s.SizeBytes = -1 },
		"size huge":       func(s *protocol.PackageInstallSpec) { s.SizeBytes = 1 << 40 },
		"file name path":  func(s *protocol.PackageInstallSpec) { s.FileName = "../setup.msi" },
		"file name empty": func(s *protocol.PackageInstallSpec) { s.FileName = "" },
		"type unknown":    func(s *protocol.PackageInstallSpec) { s.Type = "sh" },
		"type empty":      func(s *protocol.PackageInstallSpec) { s.Type = "" },
		"type case":       func(s *protocol.PackageInstallSpec) { s.Type = "MSI" },
		"too many args":   func(s *protocol.PackageInstallSpec) { s.InstallArgs = make([]string, pkginstall.MaxArgs+1) },
		"arg too long": func(s *protocol.PackageInstallSpec) {
			s.InstallArgs = []string{strings.Repeat("a", pkginstall.MaxArgBytes+1)}
		},
		"arg NUL":             func(s *protocol.PackageInstallSpec) { s.InstallArgs = []string{"a\x00b"} },
		"args for pkg":        func(s *protocol.PackageInstallSpec) { s.Type, s.InstallArgs = "pkg", []string{"-allowUntrusted"} },
		"args for deb":        func(s *protocol.PackageInstallSpec) { s.Type, s.InstallArgs = "deb", []string{"--force-all"} },
		"detection type":      func(s *protocol.PackageInstallSpec) { s.Detection = &protocol.Detection{Type: "wmi", Key: "x"} },
		"detection empty key": func(s *protocol.PackageInstallSpec) { s.Detection = &protocol.Detection{Type: "dpkg", Key: ""} },
		"detection option key": func(s *protocol.PackageInstallSpec) {
			s.Detection = &protocol.Detection{Type: "dpkg", Key: "--admindir=/tmp"}
		},
		"detection shell key": func(s *protocol.PackageInstallSpec) { s.Detection = &protocol.Detection{Type: "rpm", Key: "a; id"} },
		"detection rel file": func(s *protocol.PackageInstallSpec) {
			s.Detection = &protocol.Detection{Type: "file", Key: "relative/path"}
		},
		"detection HKCU": func(s *protocol.PackageInstallSpec) {
			s.Detection = &protocol.Detection{Type: "registry", Key: `HKCU\Software\X`}
		},
		"detection reg slash": func(s *protocol.PackageInstallSpec) {
			s.Detection = &protocol.Detection{Type: "registry", Key: `HKLM\Software\\X`}
		},
		"detection app path": func(s *protocol.PackageInstallSpec) {
			s.Detection = &protocol.Detection{Type: "app", Key: "../Foo.app"}
		},
		"detection key control": func(s *protocol.PackageInstallSpec) { s.Detection = &protocol.Detection{Type: "app", Key: "Foo\n.app"} },
		"detection min version": func(s *protocol.PackageInstallSpec) {
			s.Detection = &protocol.Detection{Type: "dpkg", Key: "tree", MinVersion: "1.0; id"}
		},
		"detection long key": func(s *protocol.PackageInstallSpec) {
			s.Detection = &protocol.Detection{Type: "file", Key: "/" + strings.Repeat("a", 2000)}
		},
	}
	for name, mutate := range cases {
		s := spec("msi", "setup.msi")
		mutate(&s)
		if err := pkginstall.ValidateInstall(&s); err == nil {
			t.Errorf("%s: accepted", name)
		}
		// And through the handler: rejected, nothing downloaded, nothing run.
		h := newHarness(t, nil, nil)
		env := windowsEnv()
		env.Types = []string{"msi", "exe", "pkg", "dmg", "deb", "rpm"}
		res, _ := h.run(pkginstall.NewInstallWithEnv(env), s)
		if res.Status != protocol.StatusRejected || h.blobs.Downloads != 0 || len(h.rec.Calls()) != 0 {
			t.Errorf("%s: status %s, downloads %d, commands %v", name, res.Status, h.blobs.Downloads, h.rec.Lines())
		}
	}
}

func TestMSIInstallArgv(t *testing.T) {
	h := newHarness(t, nil, nil)
	res, job := h.run(pkginstall.NewInstallWithEnv(windowsEnv()), spec("msi", "setup.msi", "ALLUSERS=1", "LICENSEKEY=SECRET-1234"))
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s: %s", res.Status, res.Message)
	}
	if r := installResult(t, res); !r.Installed {
		t.Fatalf("result %+v", r)
	}
	calls := h.rec.Calls()
	if len(calls) != 1 || calls[0].Path != "/fake/bin/msiexec" {
		t.Fatalf("commands: %v", h.rec.Lines())
	}
	a := calls[0].Args
	if len(a) != 6 || a[0] != "/i" || filepath.Base(a[1]) != "setup.msi" || !strings.HasPrefix(a[1], h.temp) ||
		a[2] != "/qn" || a[3] != "/norestart" || a[4] != "ALLUSERS=1" || a[5] != "LICENSEKEY=SECRET-1234" {
		t.Fatalf("argv = %q", a)
	}
	// Installer arguments are not echoed to the job output.
	if out := job.Out.String() + job.ErrOut.String(); strings.Contains(out, "SECRET") || !strings.Contains(out, "(+2 installer arguments)") {
		t.Fatalf("output leaks arguments or lacks the announcement: %q", out)
	}
	if left := h.leftovers(t); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}

	// 3010 = success, restart required.
	h = newHarness(t, nil, func(swtest.Call) swtest.Reply { return swtest.Reply{Exit: 3010} })
	res, _ = h.run(pkginstall.NewInstallWithEnv(windowsEnv()), spec("msi", "setup.msi"))
	if res.Status != protocol.StatusSucceeded || !strings.Contains(res.Message, "restart") || *res.ExitCode != 3010 {
		t.Fatalf("3010: status %s, message %q", res.Status, res.Message)
	}
	// 1603 = fatal error.
	h = newHarness(t, nil, func(swtest.Call) swtest.Reply { return swtest.Reply{Exit: 1603} })
	res, _ = h.run(pkginstall.NewInstallWithEnv(windowsEnv()), spec("msi", "setup.msi"))
	if r := installResult(t, res); res.Status != protocol.StatusFailed || r.Installed || !strings.Contains(res.Message, "1603") {
		t.Fatalf("1603: status %s result %+v message %q", res.Status, r, res.Message)
	}
}

func TestEXEInstallRunsOnlyWithInstallArgs(t *testing.T) {
	h := newHarness(t, nil, nil)
	res, _ := h.run(pkginstall.NewInstallWithEnv(windowsEnv()), spec("exe", "Setup Tool", "/S", "/D=C:\\Tools"))
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s: %s", res.Status, res.Message)
	}
	c := h.rec.Calls()[0]
	// The extension is appended when the file name lacks it.
	if filepath.Base(c.Path) != "Setup Tool.exe" || !strings.HasPrefix(c.Path, h.temp) || strings.Join(c.Args, "|") != `/S|/D=C:\Tools` {
		t.Fatalf("command = %q %q", c.Path, c.Args)
	}
	// No arguments is allowed: the package author decides.
	h = newHarness(t, nil, nil)
	if res, _ := h.run(pkginstall.NewInstallWithEnv(windowsEnv()), spec("exe", "setup.exe")); res.Status != protocol.StatusSucceeded || len(h.rec.Calls()[0].Args) != 0 {
		t.Fatalf("no-arg exe: %s %v", res.Status, h.rec.Lines())
	}
}

func TestPkgDebRpmArgv(t *testing.T) {
	h := newHarness(t, nil, nil)
	res, _ := h.run(pkginstall.NewInstallWithEnv(macEnv(h.plat, t.TempDir())), spec("pkg", "Tool.pkg"))
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("pkg: %s %s", res.Status, res.Message)
	}
	c := h.rec.Calls()[0]
	if c.Path != "/fake/bin/installer" || len(c.Args) != 4 || c.Args[0] != "-pkg" || filepath.Base(c.Args[1]) != "Tool.pkg" || c.Args[2] != "-target" || c.Args[3] != "/" || c.AsUser != nil {
		t.Fatalf("pkg command = %s", c.Line())
	}

	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv()), spec("deb", "tool_1.0_arm64.deb"))
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("deb: %s %s", res.Status, res.Message)
	}
	c = h.rec.Calls()[0]
	wantPrefix := "/fake/bin/apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=120 install -- " + h.temp
	if !strings.HasPrefix(c.Line(), wantPrefix) || !strings.HasSuffix(c.Line(), "/tool_1.0_arm64.deb") || !c.HasEnv("DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("deb command = %s", c.Line())
	}
	// Without apt-get: dpkg -i.
	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv("dpkg", "dpkg-query")), spec("deb", "tool"))
	c = h.rec.Calls()[0]
	if res.Status != protocol.StatusSucceeded || c.Path != "/fake/bin/dpkg" || c.Args[0] != "-i" || filepath.Base(c.Args[1]) != "tool.deb" {
		t.Fatalf("dpkg fallback: %s %s", res.Status, c.Line())
	}

	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv()), spec("rpm", "tool-1.0.aarch64.rpm"))
	c = h.rec.Calls()[0]
	if res.Status != protocol.StatusSucceeded || !strings.HasPrefix(c.Line(), "/fake/bin/dnf -y install -- "+h.temp) {
		t.Fatalf("rpm: %s %s", res.Status, c.Line())
	}
	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv("rpm")), spec("rpm", "tool.rpm"))
	c = h.rec.Calls()[0]
	if res.Status != protocol.StatusSucceeded || c.Path != "/fake/bin/rpm" || c.Args[0] != "-U" {
		t.Fatalf("rpm fallback: %s %s", res.Status, c.Line())
	}
	// A deb on a system without any Debian tooling.
	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv("dnf", "rpm")), spec("deb", "tool.deb"))
	if res.Status != protocol.StatusUnsupported || len(h.rec.Calls()) != 0 {
		t.Fatalf("deb without dpkg: %s %q %v", res.Status, res.Message, h.rec.Lines())
	}
}

func TestTypeNotValidForThisOS(t *testing.T) {
	cases := []struct {
		env pkginstall.Env
		typ string
	}{
		{windowsEnv(), "pkg"}, {windowsEnv(), "dmg"}, {windowsEnv(), "deb"}, {windowsEnv(), "rpm"},
		{linuxEnv(), "msi"}, {linuxEnv(), "exe"}, {linuxEnv(), "pkg"}, {linuxEnv(), "dmg"},
		{macEnv(&platform.Fake{}, "/Applications"), "msi"}, {macEnv(&platform.Fake{}, "/Applications"), "exe"},
		{macEnv(&platform.Fake{}, "/Applications"), "deb"}, {macEnv(&platform.Fake{}, "/Applications"), "rpm"},
	}
	for _, c := range cases {
		h := newHarness(t, nil, nil)
		res, _ := h.run(pkginstall.NewInstallWithEnv(c.env), spec(c.typ, "file."+c.typ))
		if res.Status != protocol.StatusUnsupported || !strings.HasPrefix(res.Message, "not supported on this OS: ") || !strings.Contains(res.Message, c.env.OSName) {
			t.Errorf("%s on %s: status %s, %q", c.typ, c.env.OSName, res.Status, res.Message)
		}
		if h.blobs.Downloads != 0 || len(h.rec.Calls()) != 0 {
			t.Errorf("%s on %s: downloaded or ran something", c.typ, c.env.OSName)
		}
		// The same for uninstall.
		res, _ = h.run(pkginstall.NewUninstallWithEnv(c.env), protocol.PackageUninstallSpec{Type: c.typ, UninstallCommand: []string{"/bin/true"}})
		if res.Status != protocol.StatusUnsupported || len(h.rec.Calls()) != 0 {
			t.Errorf("uninstall %s on %s: status %s", c.typ, c.env.OSName, res.Status)
		}
	}
}

func TestHashMismatchNeverExecutes(t *testing.T) {
	// 1. The blob client detects the mismatch.
	for name, mutate := range map[string]func(s *protocol.PackageInstallSpec, b *swtest.Blobs){
		"wrong hash": func(s *protocol.PackageInstallSpec, _ *swtest.Blobs) {
			s.SHA256 = swtest.SHA256([]byte("something else"))
		},
		"wrong size": func(s *protocol.PackageInstallSpec, _ *swtest.Blobs) { s.SizeBytes++ },
		"tampered blob": func(_ *protocol.PackageInstallSpec, b *swtest.Blobs) {
			b.Content = []byte("this is the installer package CONTENT")
		},
		"truncated blob":  func(_ *protocol.PackageInstallSpec, b *swtest.Blobs) { b.Content = b.Content[:10] },
		"client says so":  func(_ *protocol.PackageInstallSpec, b *swtest.Blobs) { b.Err = transport.ErrHashMismatch },
		"client size err": func(_ *protocol.PackageInstallSpec, b *swtest.Blobs) { b.Err = transport.ErrSizeMismatch },
		// 2. A faulty client that hands over unverified content: the handler
		// verifies the file on disk again.
		"broken client tampered": func(_ *protocol.PackageInstallSpec, b *swtest.Blobs) {
			b.Corrupt, b.Content = true, []byte("this is the installer package CONTENT")
		},
		"broken client longer": func(_ *protocol.PackageInstallSpec, b *swtest.Blobs) {
			b.Corrupt, b.Content = true, append(append([]byte{}, content...), "trailing"...)
		},
		"broken client shorter": func(_ *protocol.PackageInstallSpec, b *swtest.Blobs) { b.Corrupt, b.Content = true, content[:5] },
	} {
		for _, c := range []struct {
			env pkginstall.Env
			typ string
		}{{windowsEnv(), "msi"}, {windowsEnv(), "exe"}, {linuxEnv(), "deb"}, {linuxEnv(), "rpm"}, {macEnv(&platform.Fake{}, t.TempDir()), "pkg"}, {macEnv(&platform.Fake{}, t.TempDir()), "dmg"}} {
			h := newHarness(t, nil, nil)
			s := spec(c.typ, "package."+c.typ)
			mutate(&s, h.blobs)
			res, _ := h.run(pkginstall.NewInstallWithEnv(c.env), s)
			if res.Status != protocol.StatusRejected {
				t.Errorf("%s/%s: status %s (%s)", name, c.typ, res.Status, res.Message)
			}
			if n := len(h.rec.Calls()); n != 0 {
				t.Errorf("%s/%s: %d commands were executed: %v", name, c.typ, n, h.rec.Lines())
			}
			if left := h.leftovers(t); len(left) != 0 {
				t.Errorf("%s/%s: unverified file left on disk: %v", name, c.typ, left)
			}
		}
	}
	// A download error that is not a mismatch is a plain failure.
	h := newHarness(t, nil, nil)
	h.blobs.Err = errors.New("HTTP status 503")
	res, _ := h.run(pkginstall.NewInstallWithEnv(windowsEnv()), spec("msi", "setup.msi"))
	if res.Status != protocol.StatusFailed || len(h.rec.Calls()) != 0 {
		t.Fatalf("download error: %s %v", res.Status, h.rec.Lines())
	}
}

func TestDetectionShortCircuitAndAfterInstall(t *testing.T) {
	installed := "1.8.1-1"
	respond := func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "dpkg-query") {
			if installed == "" {
				return swtest.Reply{Exit: 1}
			}
			return swtest.Reply{Stdout: "ii \t" + installed + "\n"}
		}
		if strings.Contains(c.Line(), " install -- ") {
			installed = "2.1.0-1"
		}
		return swtest.Reply{}
	}
	withDetection := func(minVersion string) protocol.PackageInstallSpec {
		s := spec("deb", "tree.deb")
		s.Detection = &protocol.Detection{Type: "dpkg", Key: "tree", MinVersion: minVersion}
		return s
	}

	// Already installed, no minimum version: nothing is downloaded or run.
	h := newHarness(t, nil, respond)
	res, job := h.run(pkginstall.NewInstallWithEnv(linuxEnv()), withDetection(""))
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || !r.Installed || r.Version != "1.8.1-1" {
		t.Fatalf("status %s result %+v", res.Status, r)
	}
	if h.blobs.Downloads != 0 || len(h.rec.Calls()) != 1 || !strings.Contains(job.Out.String(), "Already installed (version 1.8.1-1)") {
		t.Fatalf("short circuit: downloads %d, commands %v, output %q", h.blobs.Downloads, h.rec.Lines(), job.Out.String())
	}
	// Installed at a sufficient version.
	h = newHarness(t, nil, respond)
	if res, _ := h.run(pkginstall.NewInstallWithEnv(linuxEnv()), withDetection("1.8")); res.Status != protocol.StatusSucceeded || h.blobs.Downloads != 0 {
		t.Fatalf("min version satisfied: %s, downloads %d", res.Status, h.blobs.Downloads)
	}
	// Installed but too old: the package is installed and the new version reported.
	h = newHarness(t, nil, respond)
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv()), withDetection("2.0"))
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || !r.Installed || r.Version != "2.1.0-1" {
		t.Fatalf("upgrade: status %s (%s) result %+v", res.Status, res.Message, r)
	}
	if h.blobs.Downloads != 1 || len(h.rec.Calls()) != 3 {
		t.Fatalf("upgrade: downloads %d, commands %v", h.blobs.Downloads, h.rec.Lines())
	}
	// Not installed before; the installer "succeeds" but detection still finds nothing.
	installed = ""
	h = newHarness(t, nil, func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "dpkg-query") {
			return swtest.Reply{Exit: 1}
		}
		return swtest.Reply{}
	})
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv()), withDetection(""))
	if r := installResult(t, res); res.Status != protocol.StatusFailed || r.Installed {
		t.Fatalf("undetected: status %s result %+v", res.Status, r)
	}
	// Installed afterwards, but older than required.
	h = newHarness(t, nil, func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "dpkg-query") {
			return swtest.Reply{Stdout: "ii \t1.0\n"}
		}
		return swtest.Reply{}
	})
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv()), withDetection("3.0"))
	if r := installResult(t, res); res.Status != protocol.StatusFailed || !r.Installed || r.Version != "1.0" || !strings.Contains(res.Message, "older than the required 3.0") {
		t.Fatalf("too old: status %s result %+v message %q", res.Status, r, res.Message)
	}
	// A detection type of another OS.
	h = newHarness(t, nil, nil)
	s := spec("deb", "tree.deb")
	s.Detection = &protocol.Detection{Type: "registry", Key: `HKLM\SOFTWARE\Tree`}
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv()), s)
	if res.Status != protocol.StatusUnsupported || h.blobs.Downloads != 0 || len(h.rec.Calls()) != 0 {
		t.Fatalf("foreign detection: %s %q", res.Status, res.Message)
	}
	// dpkg detection where dpkg is not installed (an rpm system).
	h = newHarness(t, nil, nil)
	s = spec("rpm", "tree.rpm")
	s.Detection = &protocol.Detection{Type: "dpkg", Key: "tree"}
	res, _ = h.run(pkginstall.NewInstallWithEnv(linuxEnv("dnf", "rpm")), s)
	if res.Status != protocol.StatusUnsupported || h.blobs.Downloads != 0 {
		t.Fatalf("dpkg detection without dpkg: %s %q", res.Status, res.Message)
	}
}

func TestDetectionTypes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	file := filepath.Join(dir, "tool.bin")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(dir, "Tool.app", "Contents")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>4.5.6</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &swtest.Recorder{Respond: func(c swtest.Call) swtest.Reply {
		switch {
		case strings.HasSuffix(c.Path, "pkgutil"):
			return swtest.Reply{Stdout: "package-id: com.example.tool\nversion: 3.2.1\ninstall-time: 1700000000\n"}
		case strings.HasSuffix(c.Path, "brew"):
			return swtest.Reply{Stdout: "wget 1.24.5\n"}
		case strings.HasSuffix(c.Path, "rpm"):
			return swtest.Reply{Stdout: "1\t4.8.0\t6.el9\n"}
		case strings.HasSuffix(c.Path, "winget"):
			return swtest.Reply{Stdout: "No installed package found matching input criteria.\n", Exit: 1}
		}
		return swtest.Reply{Exit: 1}
	}}
	plat := rec.Platform(alice)
	env := pkginstall.Env{
		OSName: "Test", Detections: []string{"file", "registry", "pkgutil", "dpkg", "rpm", "winget", "brew", "app"},
		Lookup:  swtest.Lookup("pkgutil", "rpm", "winget", "plutil", "dpkg-query"),
		Brew:    &software.Brew{Path: "/opt/homebrew/bin/brew", Plat: plat, IsRoot: func() bool { return true }},
		AppDirs: []string{dir},
		FileVersion: func(path string) string {
			if path == file {
				return "10.0.1.2"
			}
			return ""
		},
		Registry: func(key, valueName string) (software.PackageState, error) {
			if key == `SOFTWARE\Example\Tool` && valueName == "Version" {
				return software.PackageState{Installed: true, Version: "7.7"}, nil
			}
			return software.PackageState{}, nil
		},
	}
	cases := []struct {
		d       protocol.Detection
		want    software.PackageState
		command string
	}{
		{protocol.Detection{Type: "file", Key: file}, software.PackageState{Installed: true, Version: "10.0.1.2"}, ""},
		{protocol.Detection{Type: "file", Key: filepath.Join(dir, "missing")}, software.PackageState{}, ""},
		{protocol.Detection{Type: "registry", Key: `HKLM\SOFTWARE\Example\Tool`, ValueName: "Version"}, software.PackageState{Installed: true, Version: "7.7"}, ""},
		{protocol.Detection{Type: "registry", Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Other`}, software.PackageState{}, ""},
		{protocol.Detection{Type: "pkgutil", Key: "com.example.tool"}, software.PackageState{Installed: true, Version: "3.2.1"}, "/fake/bin/pkgutil --pkg-info com.example.tool"},
		{protocol.Detection{Type: "brew", Key: "wget"}, software.PackageState{Installed: true, Version: "1.24.5"}, "/opt/homebrew/bin/brew list --versions -- wget"},
		{protocol.Detection{Type: "rpm", Key: "findutils"}, software.PackageState{Installed: true, Version: "1:4.8.0-6.el9"}, `/fake/bin/rpm -q --qf %{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n -- findutils`},
		{protocol.Detection{Type: "winget", Key: "7zip.7zip"}, software.PackageState{}, "/fake/bin/winget list -e --id 7zip.7zip --accept-source-agreements --disable-interactivity"},
		{protocol.Detection{Type: "dpkg", Key: "tree"}, software.PackageState{}, `/fake/bin/dpkg-query -W -f=${db:Status-Abbrev}\t${Version}\n -- tree`},
		{protocol.Detection{Type: "app", Key: "Tool"}, software.PackageState{Installed: true, Version: "4.5.6"}, ""},
		{protocol.Detection{Type: "app", Key: "Tool.app"}, software.PackageState{Installed: true, Version: "4.5.6"}, ""},
		{protocol.Detection{Type: "app", Key: filepath.Join(dir, "Tool.app")}, software.PackageState{Installed: true, Version: "4.5.6"}, ""},
		{protocol.Detection{Type: "app", Key: "Other"}, software.PackageState{}, ""},
	}
	for _, c := range cases {
		if err := pkginstall.ValidateDetection(&c.d); err != nil {
			t.Errorf("%+v: %v", c.d, err)
			continue
		}
		before := len(rec.Calls())
		got, err := env.Detect(ctx, plat, &c.d)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %+v, %v; want %+v", c.d, got, err, c.want)
		}
		calls := rec.Calls()[before:]
		switch {
		case c.command == "" && len(calls) != 0:
			t.Errorf("%+v: unexpected commands %v", c.d, calls)
		case c.command != "" && (len(calls) != 1 || calls[0].Line() != c.command):
			t.Errorf("%+v: commands %v, want %s", c.d, calls, c.command)
		}
		if c.d.Type == "brew" && (len(calls) != 1 || calls[0].AsUser == nil) {
			t.Errorf("brew detection ran as root")
		}
	}
	if !pkginstall.Satisfied(software.PackageState{Installed: true, Version: "2.0"}, "2.0") ||
		pkginstall.Satisfied(software.PackageState{Installed: true, Version: "1.9"}, "2.0") ||
		pkginstall.Satisfied(software.PackageState{Installed: true}, "2.0") ||
		!pkginstall.Satisfied(software.PackageState{Installed: true}, "") ||
		pkginstall.Satisfied(software.PackageState{Version: "9"}, "") {
		t.Fatal("Satisfied is wrong")
	}
}

// fakeDMG answers hdiutil like a disk image with the given top-level entries.
func fakeDMG(t *testing.T, entries map[string]string, detached *int) func(c swtest.Call) swtest.Reply {
	return func(c swtest.Call) swtest.Reply {
		if !strings.HasSuffix(c.Path, "hdiutil") {
			if strings.HasSuffix(c.Path, "ditto") {
				// Copy like ditto would.
				if err := os.CopyFS(c.Args[1], os.DirFS(c.Args[0])); err != nil {
					return swtest.Reply{Exit: 1, Stderr: err.Error()}
				}
			}
			return swtest.Reply{}
		}
		switch c.Args[0] {
		case "attach":
			mount := c.Args[len(c.Args)-2]
			for name, kind := range entries {
				p := filepath.Join(mount, name)
				switch kind {
				case "dir":
					if err := os.MkdirAll(filepath.Join(p, "Contents"), 0o755); err != nil {
						t.Error(err)
					}
					_ = os.WriteFile(filepath.Join(p, "Contents", "Info.plist"), []byte(`<plist><dict><key>CFBundleShortVersionString</key><string>9.9</string></dict></plist>`), 0o644)
				case "file":
					_ = os.WriteFile(p, []byte("pkg"), 0o644)
				case "link":
					_ = os.Symlink("/Applications", p)
				}
			}
		case "detach":
			*detached++
		}
		return swtest.Reply{}
	}
}

func TestDMGInstall(t *testing.T) {
	// One application: copied into the application folder; always detached.
	detached := 0
	apps := t.TempDir()
	if err := os.MkdirAll(filepath.Join(apps, "Tool.app", "Contents", "old-version-marker"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil, fakeDMG(t, map[string]string{"Tool.app": "dir", "Applications": "link", ".background": "dir", ".DS_Store": "file"}, &detached))
	s := spec("dmg", "Tool.dmg")
	s.Detection = &protocol.Detection{Type: "app", Key: "Tool", MinVersion: "9.0"}
	res, _ := h.run(pkginstall.NewInstallWithEnv(macEnv(h.plat, apps)), s)
	if r := installResult(t, res); res.Status != protocol.StatusSucceeded || !r.Installed || r.Version != "9.9" {
		t.Fatalf("status %s (%s) result %+v", res.Status, res.Message, r)
	}
	lines := h.rec.Lines()
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "/fake/bin/hdiutil attach -nobrowse -readonly -noautoopen -mountpoint ") ||
		!strings.HasPrefix(lines[1], "/fake/bin/ditto ") || !strings.HasPrefix(lines[2], "/fake/bin/hdiutil detach ") || !strings.HasSuffix(lines[2], " -force") {
		t.Fatalf("commands:\n%s", strings.Join(lines, "\n"))
	}
	if detached != 1 {
		t.Fatalf("detached %d times", detached)
	}
	if _, err := os.Stat(filepath.Join(apps, "Tool.app", "Contents", "Info.plist")); err != nil {
		t.Fatalf("application not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(apps, "Tool.app", "Contents", "old-version-marker")); err == nil {
		t.Fatal("the old bundle was merged instead of replaced")
	}
	entries, _ := os.ReadDir(apps)
	if len(entries) != 1 {
		t.Fatalf("staging leftovers in the application folder: %v", entries)
	}

	// One installer package (an accompanying .app does not matter).
	detached = 0
	h = newHarness(t, nil, fakeDMG(t, map[string]string{"Install Tool.pkg": "file", "Uninstall Tool.app": "dir"}, &detached))
	res, _ = h.run(pkginstall.NewInstallWithEnv(macEnv(h.plat, t.TempDir())), spec("dmg", "Tool.dmg"))
	lines = h.rec.Lines()
	if res.Status != protocol.StatusSucceeded || len(lines) != 3 || !strings.HasPrefix(lines[1], "/fake/bin/installer -pkg ") ||
		!strings.HasSuffix(lines[1], "/mnt/Install Tool.pkg -target /") || detached != 1 {
		t.Fatalf("pkg in dmg: %s (%s)\n%s", res.Status, res.Message, strings.Join(lines, "\n"))
	}

	// Ambiguous or empty images are refused, and still detached.
	for name, entries := range map[string]map[string]string{
		"two apps":  {"A.app": "dir", "B.app": "dir"},
		"two pkgs":  {"A.pkg": "file", "B.pkg": "file"},
		"nothing":   {"README.txt": "file"},
		"link only": {"Evil.app": "link"},
	} {
		detached = 0
		h = newHarness(t, nil, fakeDMG(t, entries, &detached))
		res, _ = h.run(pkginstall.NewInstallWithEnv(macEnv(h.plat, t.TempDir())), spec("dmg", "Tool.dmg"))
		if res.Status != protocol.StatusFailed || !strings.Contains(res.Message, "exactly one") || detached != 1 || len(h.rec.Calls()) != 2 {
			t.Errorf("%s: status %s (%s), detached %d, commands %v", name, res.Status, res.Message, detached, h.rec.Lines())
		}
	}

	// The image cannot be attached: nothing else runs.
	h = newHarness(t, nil, func(c swtest.Call) swtest.Reply {
		return swtest.Reply{Exit: 1, Stderr: "hdiutil: attach failed - image not recognized\n"}
	})
	res, _ = h.run(pkginstall.NewInstallWithEnv(macEnv(h.plat, t.TempDir())), spec("dmg", "Tool.dmg"))
	if res.Status != protocol.StatusFailed || len(h.rec.Calls()) != 1 {
		t.Fatalf("attach failure: %s %v", res.Status, h.rec.Lines())
	}
	// The installer inside fails: still detached.
	detached = 0
	inner := fakeDMG(t, map[string]string{"Tool.pkg": "file"}, &detached)
	h = newHarness(t, nil, func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "installer") {
			return swtest.Reply{Exit: 1, Stderr: "installer: The upgrade failed.\n"}
		}
		return inner(c)
	})
	res, _ = h.run(pkginstall.NewInstallWithEnv(macEnv(h.plat, t.TempDir())), spec("dmg", "Tool.dmg"))
	if res.Status != protocol.StatusFailed || detached != 1 {
		t.Fatalf("failing installer: %s, detached %d", res.Status, detached)
	}
}

func TestPackageUninstall(t *testing.T) {
	// MSI by product code.
	h := newHarness(t, nil, nil)
	res, _ := h.run(pkginstall.NewUninstallWithEnv(windowsEnv()), protocol.PackageUninstallSpec{Type: "msi", ProductCode: "{23170F69-40C1-2702-2408-000001000000}"})
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("msi: %s %s", res.Status, res.Message)
	}
	if r, ok := res.Result.(protocol.PackageUninstallResult); !ok || r.Installed {
		t.Fatalf("result %+v", res.Result)
	}
	if got := h.rec.Lines(); len(got) != 1 || got[0] != "/fake/bin/msiexec /x {23170F69-40C1-2702-2408-000001000000} /qn /norestart" {
		t.Fatalf("msi command = %v", got)
	}
	// "Product not installed" is the desired state.
	h = newHarness(t, nil, func(swtest.Call) swtest.Reply { return swtest.Reply{Exit: 1605} })
	if res, _ := h.run(pkginstall.NewUninstallWithEnv(windowsEnv()), protocol.PackageUninstallSpec{Type: "msi", ProductCode: "{23170F69-40C1-2702-2408-000001000000}"}); res.Status != protocol.StatusSucceeded {
		t.Fatalf("1605: %s", res.Status)
	}

	// A bare well-known tool is resolved in the trusted directories.
	h = newHarness(t, nil, nil)
	res, job := h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), protocol.PackageUninstallSpec{Type: "deb", UninstallCommand: []string{"apt-get", "-y", "remove", "tree"}})
	if res.Status != protocol.StatusSucceeded || h.rec.Lines()[0] != "/fake/bin/apt-get -y remove tree" {
		t.Fatalf("bare tool: %s %v", res.Status, h.rec.Lines())
	}
	if strings.Contains(job.Out.String(), "remove") {
		t.Fatalf("uninstall arguments echoed: %q", job.Out.String())
	}
	// An absolute path to an existing program.
	prog := filepath.Join(t.TempDir(), "uninstall.sh")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), protocol.PackageUninstallSpec{Type: "rpm", UninstallCommand: []string{prog, "--silent"}})
	if res.Status != protocol.StatusSucceeded || h.rec.Lines()[0] != prog+" --silent" {
		t.Fatalf("absolute path: %s %v", res.Status, h.rec.Lines())
	}
	// Homebrew runs as the console user even here.
	h = newHarness(t, alice, nil)
	res, _ = h.run(pkginstall.NewUninstallWithEnv(macEnv(h.plat, t.TempDir())), protocol.PackageUninstallSpec{Type: "pkg", UninstallCommand: []string{"brew", "uninstall", "--cask", "tool"}})
	if c := h.rec.Calls()[0]; res.Status != protocol.StatusSucceeded || c.Line() != "/opt/homebrew/bin/brew uninstall --cask tool" || c.AsUser == nil {
		t.Fatalf("brew: %s %+v", res.Status, c)
	}
	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewUninstallWithEnv(macEnv(h.plat, t.TempDir())), protocol.PackageUninstallSpec{Type: "pkg", UninstallCommand: []string{"brew", "uninstall", "tool"}})
	if res.Status != protocol.StatusFailed || res.Message != "no logged-in user" || len(h.rec.Calls()) != 0 {
		t.Fatalf("brew without user: %s %q", res.Status, res.Message)
	}

	// Refused commands.
	rejected := []protocol.PackageUninstallSpec{
		{Type: "deb"},
		{Type: "deb", UninstallCommand: []string{}},
		{Type: "deb", UninstallCommand: []string{""}},
		{Type: "deb", UninstallCommand: []string{"sh", "-c", "rm -rf /"}},
		{Type: "deb", UninstallCommand: []string{"bash", "-c", "id"}},
		{Type: "deb", UninstallCommand: []string{"./uninstall.sh"}},
		{Type: "deb", UninstallCommand: []string{"relative/uninstall.sh"}},
		{Type: "deb", UninstallCommand: []string{"apt-get; id"}},
		{Type: "deb", UninstallCommand: []string{"-rf"}},
		{Type: "deb", UninstallCommand: []string{"apt-get", "a\x00b"}},
		{Type: "deb", UninstallCommand: []string{"msiexec", "/x", "x"}}, // not a tool of this OS
		{Type: "deb", ProductCode: "{23170F69-40C1-2702-2408-000001000000}"},
		{Type: "zip", UninstallCommand: []string{"apt-get"}},
		{Type: "deb", UninstallCommand: []string{"apt-get"}, Detection: &protocol.Detection{Type: "dpkg", Key: "-x"}},
	}
	for i, s := range rejected {
		h = newHarness(t, nil, nil)
		res, _ = h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), s)
		if res.Status != protocol.StatusRejected || len(h.rec.Calls()) != 0 {
			t.Errorf("case %d %+v: status %s (%s), commands %v", i, s, res.Status, res.Message, h.rec.Lines())
		}
	}
	for _, code := range []string{"23170F69-40C1-2702-2408-000001000000", "{23170F69}", "{23170F69-40C1-2702-2408-000001000000} /qb", "{g3170F69-40C1-2702-2408-000001000000}"} {
		h = newHarness(t, nil, nil)
		res, _ = h.run(pkginstall.NewUninstallWithEnv(windowsEnv()), protocol.PackageUninstallSpec{Type: "msi", ProductCode: code})
		if res.Status != protocol.StatusRejected || len(h.rec.Calls()) != 0 {
			t.Errorf("product code %q: status %s", code, res.Status)
		}
	}
	// Homebrew by absolute path would run as root: refused.
	h = newHarness(t, alice, nil)
	res, _ = h.run(pkginstall.NewUninstallWithEnv(macEnv(h.plat, t.TempDir())), protocol.PackageUninstallSpec{Type: "pkg", UninstallCommand: []string{"/opt/homebrew/bin/brew", "uninstall", "tool"}})
	if res.Status != protocol.StatusRejected || len(h.rec.Calls()) != 0 {
		t.Fatalf("brew by path: %s %v", res.Status, h.rec.Lines())
	}
	// A missing absolute program fails without running anything.
	h = newHarness(t, nil, nil)
	res, _ = h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), protocol.PackageUninstallSpec{Type: "deb", UninstallCommand: []string{filepath.Join(t.TempDir(), "missing")}})
	if res.Status != protocol.StatusFailed || len(h.rec.Calls()) != 0 {
		t.Fatalf("missing program: %s", res.Status)
	}
}

func TestPackageUninstallDetection(t *testing.T) {
	installed := true
	respond := func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "dpkg-query") {
			if installed {
				return swtest.Reply{Stdout: "ii \t1.0\n"}
			}
			return swtest.Reply{Exit: 1}
		}
		installed = false
		return swtest.Reply{}
	}
	s := protocol.PackageUninstallSpec{Type: "deb", UninstallCommand: []string{"apt-get", "-y", "remove", "tree"}, Detection: &protocol.Detection{Type: "dpkg", Key: "tree"}}
	h := newHarness(t, nil, respond)
	res, _ := h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), s)
	if r := res.Result.(protocol.PackageUninstallResult); res.Status != protocol.StatusSucceeded || r.Installed || len(h.rec.Calls()) != 3 {
		t.Fatalf("status %s result %+v commands %v", res.Status, r, h.rec.Lines())
	}
	// Already gone: nothing is run.
	h = newHarness(t, nil, respond)
	res, job := h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), s)
	if res.Status != protocol.StatusSucceeded || len(h.rec.Calls()) != 1 || !strings.Contains(job.Out.String(), "Not installed") {
		t.Fatalf("short circuit: %s %v", res.Status, h.rec.Lines())
	}
	// The command "succeeds" but the package is still there.
	h = newHarness(t, nil, func(c swtest.Call) swtest.Reply {
		if strings.HasSuffix(c.Path, "dpkg-query") {
			return swtest.Reply{Stdout: "ii \t1.0\n"}
		}
		return swtest.Reply{}
	})
	res, _ = h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), s)
	if r := res.Result.(protocol.PackageUninstallResult); res.Status != protocol.StatusFailed || !r.Installed {
		t.Fatalf("still installed: %s %+v", res.Status, r)
	}
	// The command fails and there is no detection: assumed still installed.
	h = newHarness(t, nil, func(swtest.Call) swtest.Reply { return swtest.Reply{Exit: 2} })
	res, _ = h.run(pkginstall.NewUninstallWithEnv(linuxEnv()), protocol.PackageUninstallSpec{Type: "deb", UninstallCommand: []string{"dpkg", "-r", "tree"}})
	if r := res.Result.(protocol.PackageUninstallResult); res.Status != protocol.StatusFailed || !r.Installed || *res.ExitCode != 2 {
		t.Fatalf("failing command: %s %+v", res.Status, r)
	}
}
