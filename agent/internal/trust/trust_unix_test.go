//go:build !windows

package trust

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func TestLoadRefusesWritableTrustFiles(t *testing.T) {
	dir := t.TempDir()
	caPath, trustPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "trust.json")
	if err := Install(caPath, trustPath, testCA(t, "CA", true), []protocol.CommandKey{testKey(t, "k1")}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{caPath, trustPath} {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, fi.Mode().Perm())
		}
	}
	if err := os.Chmod(trustPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(caPath, trustPath); err == nil {
		t.Fatal("a world-writable trust.json was loaded")
	}
}
