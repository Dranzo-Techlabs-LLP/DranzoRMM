//go:build windows

package files

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// checkOSPath refuses the Win32 device namespace (\\.\PhysicalDrive0,
// \\.\pipe\..., \\?\GLOBALROOT\...): the file browser is for files.
func checkOSPath(p string) error {
	norm := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	if strings.HasPrefix(norm, `\\.\`) || strings.HasPrefix(norm, `\\?\globalroot`) || strings.HasPrefix(norm, `\??\`) {
		return errors.New("device paths are not allowed")
	}
	return nil
}

func openForRead(path string) (*os.File, error) { return os.Open(path) }

// renameNoReplace moves oldpath to newpath and fails with os.ErrExist when
// newpath exists (MoveFileEx without MOVEFILE_REPLACE_EXISTING).
func renameNoReplace(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return os.ErrExist
	}
	return err
}

// copyOwnerAndMode: on Windows the new file keeps the ACL it inherited from
// the directory (the explicit ACL of the replaced file is not copied). A
// read-only destination cannot be replaced; the job then fails.
func copyOwnerAndMode(string, os.FileInfo) error { return nil }
