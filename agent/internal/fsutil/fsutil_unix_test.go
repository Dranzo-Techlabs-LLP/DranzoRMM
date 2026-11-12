//go:build !windows

package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicIsOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v, want 0700", fi.Mode().Perm())
	}
	// An existing, too-open directory is tightened.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v after re-ensure", fi.Mode().Perm())
	}

	path := filepath.Join(dir, "device.key")
	if err := WriteFileAtomic(path, []byte("secret-1")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v, want 0600", fi.Mode().Perm())
	}
	// Replacing keeps the permissions and leaves no temp files behind.
	if err := WriteFileAtomic(path, []byte("secret-2")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "secret-2" {
		t.Fatalf("content %q", data)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v after replace", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestCheckPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	if err := WriteFileAtomic(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(path); err != nil {
		t.Fatalf("owner-only file refused: %v", err)
	}
	if _, err := ReadPrivateFile(path, 100); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o666, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckPrivate(path); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("mode %04o accepted: %v", mode, err)
		}
		if _, err := ReadPrivateFile(path, 100); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("mode %04o: file was read: %v", mode, err)
		}
	}
	// A symlink is never followed for a protected file.
	_ = os.Chmod(path, 0o600)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(link); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("symlink accepted: %v", err)
	}
	if err := CheckPrivate(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestReadFileLimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileLimited(path, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileLimited(path, 99); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}
