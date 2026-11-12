//go:build !windows

package update

import (
	"fmt"
	"os"
	"syscall"
)

// renameAsideDefault: on Unix rename(2) replaces a running executable atomically.
const renameAsideDefault = false

// matchOwnerAndMode gives dst the owner and permissions of ref (the installed
// executable): normally root-owned 0755. The result is never writable by
// group or others and always executable by its owner.
func matchOwnerAndMode(dst, ref string) error {
	fi, err := os.Stat(ref)
	if err != nil {
		return err
	}
	mode := (fi.Mode().Perm() | 0o500) &^ 0o022
	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("set permissions of %s: %w", dst, err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		if err := os.Chown(dst, int(st.Uid), int(st.Gid)); err != nil {
			return fmt.Errorf("set owner of %s: %w", dst, err)
		}
	}
	return nil
}

// syncDir flushes a directory so that a completed rename survives a power loss.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
