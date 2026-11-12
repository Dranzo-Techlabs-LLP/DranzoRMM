//go:build windows

package fsutil

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// ErrInsecurePermissions is returned by CheckPrivate when a protected file is
// not adequately protected. On Windows protection is enforced by the ACL that
// is applied when the file is written.
var ErrInsecurePermissions = errors.New("insecure permissions")

// SDDL: protected DACL (no inheritance from the parent), full control for
// LocalSystem (SY) and the built-in Administrators group (BA) only.
const (
	sddlDirBase  = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sddlFileBase = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)"
)

// devUserACE returns an extra ACE for the current user when the process is
// NOT elevated (development and test runs with --data-dir). A service running
// as LocalSystem, or an elevated administrator, gets the strict ACL only.
func devUserACE(dir bool) string {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return ""
	}
	tu, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	sid := tu.User.Sid.String()
	if sid == "" {
		return ""
	}
	if dir {
		return "(A;OICI;FA;;;" + sid + ")"
	}
	return "(A;;FA;;;" + sid + ")"
}

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

func protectDir(dir string) error { return applySDDL(dir, sddlDirBase+devUserACE(true)) }

func protectFile(path string) error { return applySDDL(path, sddlFileBase+devUserACE(false)) }

// ProtectFile applies the restrictive file protection to an existing file.
func ProtectFile(path string) error { return protectFile(path) }

// CheckPrivate is a no-op on Windows: the SYSTEM + Administrators ACL is
// applied (with inheritance disabled) whenever the agent writes a protected
// file or creates its data directory.
func CheckPrivate(_ string) error { return nil }

func syncDir(_ string) {}

// IsElevated reports whether the process runs elevated (Administrator or LocalSystem).
func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
