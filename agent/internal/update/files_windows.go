//go:build windows

package update

// renameAsideDefault: a running image cannot be replaced on Windows, only renamed.
const renameAsideDefault = true

// matchOwnerAndMode is a no-op on Windows: the new binary is created inside
// the program directory and therefore inherits that directory's ACL, exactly
// like the binary the installer placed there.
func matchOwnerAndMode(_, _ string) error { return nil }

// syncDir is a no-op on Windows: NTFS journals renames, and a directory
// handle cannot be flushed through the os package.
func syncDir(_ string) {}
