//go:build !windows

package files

import (
	"errors"
	"os"
	"syscall"
)

func checkOSPath(string) error { return nil }

// openForRead opens without blocking: should the path have been replaced by
// a FIFO after the check, open returns at once and the second check on the
// opened file refuses it.
func openForRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}

// renameNoReplace moves oldpath to newpath and fails with os.ErrExist when
// newpath exists. A hard link is atomic and never replaces; the temporary
// name is removed afterwards.
func renameNoReplace(oldpath, newpath string) error {
	err := os.Link(oldpath, newpath)
	switch {
	case err == nil:
		return os.Remove(oldpath)
	case errors.Is(err, os.ErrExist):
		return os.ErrExist
	}
	// File systems without hard links (FAT, some network shares): check and
	// rename. The window between the two is tiny and only another root-level
	// writer could use it.
	if _, lerr := os.Lstat(newpath); lerr == nil {
		return os.ErrExist
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return lerr
	}
	return os.Rename(oldpath, newpath)
}

// copyOwnerAndMode gives the new file the owner and permission bits of the
// file it replaces. Set-uid, set-gid and sticky bits are never carried over.
func copyOwnerAndMode(path string, existing os.FileInfo) error {
	if st, ok := existing.Sys().(*syscall.Stat_t); ok {
		if err := os.Lchown(path, int(st.Uid), int(st.Gid)); err != nil && os.Geteuid() == 0 {
			return err
		}
	}
	return os.Chmod(path, existing.Mode().Perm())
}
