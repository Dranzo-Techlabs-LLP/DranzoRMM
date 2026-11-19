package update

import (
	"os"
	"path/filepath"
	"testing"
)

// syncFile must open the file for writing (Windows refuses to flush a
// read-only handle) and must not fail on a file whose mode forbids writing.
func TestSyncFile(t *testing.T) {
	dir := t.TempDir()
	rw := filepath.Join(dir, "agent.new")
	if err := os.WriteFile(rw, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncFile(rw); err != nil {
		t.Fatalf("writable file: %v", err)
	}
	ro := filepath.Join(dir, "agent.ro")
	if err := os.WriteFile(ro, []byte("binary"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := syncFile(ro); err != nil {
		t.Fatalf("read-only file: %v", err)
	}
	if err := syncFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file: no error")
	}
}
