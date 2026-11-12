//go:build !windows

package config

import (
	"errors"
	"os"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
)

func TestConfigFilePermissions(t *testing.T) {
	p := testPaths(t)
	for _, dir := range []string{p.StateDir, p.ConfigDir} {
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode %v, want 0700", dir, fi.Mode().Perm())
		}
	}
	if err := Save(p, &Config{ServerURL: "https://rmm.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveBootstrap(p, &Bootstrap{ServerURL: "https://rmm.example.com", Token: "dz_enroll_abcdefgh"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p.ConfigFile(), p.BootstrapFile()} {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, want 0600", f, fi.Mode().Perm())
		}
	}
	// A config or bootstrap file that others can read or write is refused, not used.
	if err := os.Chmod(p.BootstrapFile(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBootstrap(p); !errors.Is(err, fsutil.ErrInsecurePermissions) {
		t.Fatalf("world-readable bootstrap.json accepted: %v", err)
	}
	if err := os.Chmod(p.ConfigFile(), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, fsutil.ErrInsecurePermissions) {
		t.Fatalf("world-writable config.json accepted: %v", err)
	}
}
