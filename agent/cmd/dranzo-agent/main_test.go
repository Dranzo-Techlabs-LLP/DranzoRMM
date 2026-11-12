package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/buildinfo"
	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
	"github.com/dranzo/dranzormm/agent/internal/trust"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = realMain(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersionAndUsage(t *testing.T) {
	code, out, _ := run("version")
	if code != 0 || !strings.Contains(out, buildinfo.Version) {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, _, errOut := run(); code != 2 || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("no args: %d %q", code, errOut)
	}
	if code, _, errOut := run("frobnicate"); code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown command: %d %q", code, errOut)
	}
}

func TestInstallValidatesInput(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"http server", []string{"install", "--server", "http://rmm.example.com", "--token", "dz_enroll_abcdefgh12345678", "--data-dir", dir}, "https"},
		{"no token", []string{"install", "--server", "https://rmm.example.com", "--data-dir", dir}, "enrollment token"},
		{"malformed token", []string{"install", "--server", "https://rmm.example.com", "--token", "hunter2", "--data-dir", dir}, "enrollment token"},
		{"ca without trust", []string{"install", "--server", "https://rmm.example.com", "--token", "dz_enroll_abcdefgh12345678", "--ca-file", "x.pem", "--data-dir", dir}, "together"},
	}
	for _, c := range cases {
		code, _, errOut := run(c.args...)
		if code != 1 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: code %d, stderr %q", c.name, code, errOut)
		}
		// Whatever went wrong, the token is never echoed back.
		if strings.Contains(errOut, "abcdefgh12345678") || strings.Contains(errOut, "hunter2") {
			t.Errorf("%s: token echoed in the error output: %q", c.name, errOut)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("a refused install wrote files: %v", entries)
	}
}

func TestInstallAndUninstallNeedElevation(t *testing.T) {
	if fsutil.IsElevated() {
		t.Skip("running elevated: the real install path would register a service")
	}
	dir := t.TempDir()
	code, _, errOut := run("install", "--server", "https://rmm.example.com", "--token", "dz_enroll_abcdefgh12345678", "--data-dir", dir)
	if code != 1 || !strings.Contains(errOut, "root") || !strings.Contains(errOut, "Administrator") {
		t.Fatalf("install as a normal user: %d %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "bootstrap.json")); !os.IsNotExist(err) {
		t.Fatal("bootstrap.json written although install was refused")
	}
	code, _, errOut = run("uninstall", "--data-dir", dir)
	if code != 1 || !strings.Contains(errOut, "root") {
		t.Fatalf("uninstall as a normal user: %d %q", code, errOut)
	}
}

func TestWriteInstallFilesReplacesOldIdentity(t *testing.T) {
	srv, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	paths := config.ResolvePaths(filepath.Join(t.TempDir(), "data"))
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	// Fresh install: trust anchors and bootstrap.json are written, owner-only.
	replaced, err := writeInstallFiles(paths, srv.URL, srv.Token, srv.CAPEM, srv.TrustKeys())
	if err != nil || replaced {
		t.Fatalf("fresh install: replaced=%v err=%v", replaced, err)
	}
	b, err := config.LoadBootstrap(paths)
	if err != nil || b.Token != srv.Token || b.ServerURL != srv.URL {
		t.Fatalf("bootstrap: %+v %v", b, err)
	}
	if _, err := trust.Load(paths.CAFile(), paths.TrustFile()); err != nil {
		t.Fatal(err)
	}
	// Leftovers of an earlier installation: the old identity must not survive,
	// otherwise the new token would be erased without a new enrollment.
	for _, f := range []string{paths.KeyFile(), paths.CertFile(), paths.ConfigFile()} {
		if err := os.WriteFile(f, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	replaced, err = writeInstallFiles(paths, srv.URL, srv.Token, nil, nil) // trust store already present
	if err != nil || !replaced {
		t.Fatalf("re-install: replaced=%v err=%v", replaced, err)
	}
	for _, f := range []string{paths.KeyFile(), paths.CertFile(), paths.ConfigFile()} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s survived a re-install", f)
		}
	}
	// Without trust files and without compiled-in anchors a first install is refused.
	empty := config.ResolvePaths(filepath.Join(t.TempDir(), "empty"))
	if err := empty.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := writeInstallFiles(empty, srv.URL, srv.Token, nil, nil); err == nil || !strings.Contains(err.Error(), "--ca-file") {
		t.Fatalf("install without trust anchors: %v", err)
	}
	if _, err := os.Stat(empty.BootstrapFile()); !os.IsNotExist(err) {
		t.Fatal("token written although the install was refused")
	}
}

func TestStatusBeforeEnrollment(t *testing.T) {
	code, out, errOut := run("status", "--data-dir", t.TempDir())
	if code != 0 {
		t.Fatalf("status: %d %q", code, errOut)
	}
	for _, want := range []string{"Agent version:", "Service:", "not enrolled", "Certificate:    -", "Connection:"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
}
