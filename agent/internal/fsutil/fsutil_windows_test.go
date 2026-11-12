//go:build windows

package fsutil

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCheckPrivateWindows exercises the DACL check behind ReadPrivateFile.
// It only touches files in a temporary directory.
func TestCheckPrivateWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); err != nil {
		t.Fatalf("protected directory refused: %v", err)
	}
	path := filepath.Join(dir, "trust.json")
	if err := WriteFileAtomic(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(path); err != nil {
		t.Fatalf("file written by WriteFileAtomic refused: %v", err)
	}
	if data, err := ReadPrivateFile(path, 100); err != nil || string(data) != "{}" {
		t.Fatalf("ReadPrivateFile: %q %v", data, err)
	}

	for name, sddl := range map[string]string{
		"everyone read":   "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)",
		"users write":     "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)",
		"null DACL":       "D:NO_ACCESS_CONTROL",
		"authenticated r": "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;AU)",
	} {
		if err := applySDDL(path, sddl); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := CheckPrivate(path); !errors.Is(err, ErrInsecurePermissions) {
			t.Errorf("%s: CheckPrivate = %v", name, err)
		}
		if _, err := ReadPrivateFile(path, 100); !errors.Is(err, ErrInsecurePermissions) {
			t.Errorf("%s: ReadPrivateFile = %v", name, err)
		}
	}

	for name, sddl := range map[string]string{
		"protected":           sddlFileBase,
		"deny guests":         "D:PAI(D;;FA;;;BG)(A;;FA;;;SY)(A;;FA;;;BA)",
		"everyone attributes": "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x100080;;;WD)",
		"trustedinstaller":    "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + trustedInstallerSID + ")",
	} {
		if err := applySDDL(path, sddl); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := CheckPrivate(path); err != nil {
			t.Errorf("%s: CheckPrivate = %v", name, err)
		}
	}

	// Inherit-only ACEs on a directory apply to children, not to it.
	if err := applySDDL(dir, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FR;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); err != nil {
		t.Errorf("inherit-only ACE: %v", err)
	}
	if err := protectDir(dir); err != nil {
		t.Fatal(err)
	}

	// Reparse points are refused.
	target := filepath.Join(dir, "target")
	if err := EnsurePrivateDir(target); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junction")
	if out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/D", "/C", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Logf("mklink /J failed, junction case skipped: %v %s", err, out)
	} else if err := CheckPrivate(junction); !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("junction: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Logf("symlink not permitted, symlink case skipped: %v", err)
	} else if err := CheckPrivate(link); !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("symlink: %v", err)
	}
	if err := CheckPrivate(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}
