//go:build !windows

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrInsecurePermissions is returned by CheckPrivate when a protected file or
// directory is accessible to users other than its owner.
var ErrInsecurePermissions = errors.New("insecure permissions")

func protectDir(dir string) error { return os.Chmod(dir, 0o700) } //nolint:gosec // directories need the execute bit

func protectFile(path string) error { return os.Chmod(path, 0o600) }

// ProtectFile applies the restrictive file protection to an existing file.
func ProtectFile(path string) error { return protectFile(path) }

// CheckPrivate verifies that path is a regular file or directory (not a
// symlink), is owned by the current user or root, and grants no access to
// group or others.
func CheckPrivate(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: %w: is a symbolic link", path, ErrInsecurePermissions)
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return fmt.Errorf("%s: %w: not a regular file", path, ErrInsecurePermissions)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s: %w: mode %04o allows group/other access", path, ErrInsecurePermissions, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		euid := os.Geteuid()
		if st.Uid != 0 && euid >= 0 && uint64(st.Uid) != uint64(euid) {
			return fmt.Errorf("%s: %w: owned by uid %d", path, ErrInsecurePermissions, st.Uid)
		}
	}
	return nil
}

// syncDir flushes the directory entry after a rename (best effort).
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// IsElevated reports whether the process runs as root.
func IsElevated() bool { return os.Geteuid() == 0 }
