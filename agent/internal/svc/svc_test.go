package svc

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func verifier(t *testing.T, code string) *protocol.UninstallCode {
	t.Helper()
	salt := []byte("0123456789abcdef")
	hash, err := pbkdf2.Key(sha256.New, code, salt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.UninstallCode{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Iterations: 1000,
		Hash:       base64.StdEncoding.EncodeToString(hash),
	}
}

func TestVerifyUninstallCode(t *testing.T) {
	if err := VerifyUninstallCode("", nil); err != nil {
		t.Fatalf("no code configured must allow uninstall: %v", err)
	}
	uc := verifier(t, "correct horse")
	if err := VerifyUninstallCode("correct horse", uc); err != nil {
		t.Fatalf("right code refused: %v", err)
	}
	for _, wrong := range []string{"", "Correct horse", "correct horse ", "x"} {
		if err := VerifyUninstallCode(wrong, uc); !errors.Is(err, ErrUninstallCode) {
			t.Fatalf("code %q: %v", wrong, err)
		}
	}
	// RFC 7914 section 11 test vector for PBKDF2-HMAC-SHA256 (password "passwd", salt "salt",
	// 1 iteration; first 32 bytes 55ac046e...0dacbc), cross-checked with Python hashlib.
	known := &protocol.UninstallCode{
		Salt:       base64.StdEncoding.EncodeToString([]byte("salt")),
		Iterations: 1,
		Hash:       "VawEblbjCJ/sFpHCJUS2BflBhSFt3gRl5oudV8INrLw=",
	}
	if err := VerifyUninstallCode("passwd", known); err != nil {
		t.Fatalf("known PBKDF2 vector failed: %v", err)
	}
	// A damaged verifier never lets anyone through.
	for _, bad := range []*protocol.UninstallCode{
		{Salt: "!!", Iterations: 1000, Hash: uc.Hash},
		{Salt: uc.Salt, Iterations: 0, Hash: uc.Hash},
		{Salt: uc.Salt, Iterations: 1000, Hash: "c2hvcnQ="},
	} {
		if err := VerifyUninstallCode("correct horse", bad); err == nil {
			t.Fatalf("damaged verifier accepted: %+v", bad)
		}
	}
}

func TestServiceIsVisibleAndDescribed(t *testing.T) {
	cfg := newConfig([]string{"run"})
	if cfg.DisplayName != "DranzoRMM Agent" {
		t.Fatalf("display name %q", cfg.DisplayName)
	}
	if !strings.Contains(strings.ToLower(cfg.Name), "dranzo") {
		t.Fatalf("service name %q does not say what it is", cfg.Name)
	}
	desc := strings.ToLower(cfg.Description)
	for _, want := range []string{"management agent", "it provider", "removed"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description should mention %q: %s", want, cfg.Description)
		}
	}
}

func TestPurgeRemovesOnlyAgentFiles(t *testing.T) {
	root := t.TempDir()
	p := config.ResolvePaths(filepath.Join(root, "data"))
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p.ConfigFile(), p.KeyFile(), p.CertFile(), p.CAFile(), p.TrustFile(), p.NoncesFile(), p.LogFile(), p.BootstrapFile()} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	foreign := filepath.Join(p.StateDir, "not-ours.txt")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	Purge(p)
	entries, _ := os.ReadDir(p.StateDir)
	if len(entries) != 1 || entries[0].Name() != "not-ours.txt" {
		t.Fatalf("after purge: %v", entries)
	}
	// With nothing foreign left the directory itself goes too.
	_ = os.Remove(foreign)
	Purge(p)
	if _, err := os.Stat(p.StateDir); !os.IsNotExist(err) {
		t.Fatal("empty data directory not removed")
	}
}
