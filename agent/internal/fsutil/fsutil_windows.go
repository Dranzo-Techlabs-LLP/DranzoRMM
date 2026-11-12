//go:build windows

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrInsecurePermissions is returned by CheckPrivate when a protected file is
// not adequately protected (a reparse point, or a DACL that grants access to
// someone other than SYSTEM, Administrators or the current user).
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

// Access-mask bits that only expose metadata (synchronize, read the security
// descriptor, read attributes). An ACE that grants nothing else is harmless.
const benignAccess = windows.SYNCHRONIZE | windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES

// trustedInstallerSID is NT SERVICE\TrustedInstaller (owner of system files).
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// trustedSID reports whether sid may hold access to a protected file:
// LocalSystem, the built-in Administrators group, TrustedInstaller, or the
// user this process runs as (the development ACE added by devUserACE).
func trustedSID(sid *windows.SID) bool {
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	s := sid.String()
	if s == trustedInstallerSID {
		return true
	}
	if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && tu.User.Sid.String() == s {
		return true
	}
	return false
}

// CheckPrivate verifies that path is a regular file or directory (not a
// symbolic link, junction or other reparse point) whose DACL grants access
// (beyond reading metadata) only to LocalSystem, Administrators,
// TrustedInstaller or the current user. Files the agent writes carry the
// protected SYSTEM + Administrators ACL (see protectFile), so they pass; a
// file that inherited, say, "Users: read" from an unprotected directory does
// not. Deny ACEs and inherit-only ACEs (which apply to children only) are
// ignored. The owner is not checked: elevated administrators create files
// owned either by themselves or by the Administrators group, depending on
// local policy.
func CheckPrivate(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: %w: is a symbolic link", path, ErrInsecurePermissions)
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return fmt.Errorf("%s: %w: not a regular file or directory (reparse point or device)", path, ErrInsecurePermissions)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the security descriptor of %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		return fmt.Errorf("%s: %w: no DACL (everyone has full access)", path, ErrInsecurePermissions)
	}
	if err != nil {
		return fmt.Errorf("read the DACL of %s: %w", path, err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case 5, 9, 11: // allowed object / callback / callback-object ACEs: never on agent files
			return fmt.Errorf("%s: %w: unexpected access-allowed ACE type %d", path, ErrInsecurePermissions, ace.Header.AceType)
		default: // deny and audit ACEs do not grant access
			continue
		}
		if ace.Mask&^benignAccess == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: Win32 interop, the SID follows the ACE header in memory
		if !trustedSID(sid) {
			return fmt.Errorf("%s: %w: access 0x%x granted to %s", path, ErrInsecurePermissions, uint32(ace.Mask), sid.String())
		}
	}
	return nil
}

func syncDir(_ string) {}

// IsElevated reports whether the process runs elevated (Administrator or LocalSystem).
func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
