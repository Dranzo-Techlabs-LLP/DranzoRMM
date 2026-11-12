//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
)

// Live Windows test (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit): the ACLs of a data directory created by the real
// code, in a temporary directory (the real C:\ProgramData\DranzoRMM is not
// touched).

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

type aceInfo struct {
	sid   string
	typ   uint8
	flags uint8
	mask  uint32
}

// readACL returns whether the DACL is protected and its ACEs.
func readACL(t *testing.T, path string) (protected bool, aces []aceInfo, sddl string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read security descriptor of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL of %s: %v", path, err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		aces = append(aces, aceInfo{sid: sid.String(), typ: ace.Header.AceType, flags: ace.Header.AceFlags, mask: uint32(ace.Mask)})
	}
	return control&windows.SE_DACL_PROTECTED != 0, aces, sd.String()
}

const (
	sidSystem = "S-1-5-18"
	sidAdmins = "S-1-5-32-544"
	fullMask  = 0x1F01FF
)

func expectSystemAdminsOnly(t *testing.T, path string, dir bool) {
	t.Helper()
	protected, aces, sddl := readACL(t, path)
	t.Logf("%s: %s", path, sddl)
	if !protected {
		t.Errorf("%s: DACL inherits from the parent", path)
	}
	elevated := fsutil.IsElevated()
	seen := map[string]bool{}
	for _, a := range aces {
		if a.typ != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("%s: unexpected ACE type %d", path, a.typ)
		}
		if a.flags&windows.INHERITED_ACE != 0 {
			t.Errorf("%s: inherited ACE %+v", path, a)
		}
		if dir && a.flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			t.Errorf("%s: directory ACE without OI/CI: %+v", path, a)
		}
		switch a.sid {
		case sidSystem, sidAdmins:
			if a.mask != fullMask {
				t.Errorf("%s: %s has mask 0x%x, want full control", path, a.sid, a.mask)
			}
		default:
			if elevated {
				t.Errorf("%s: access for %s (mask 0x%x)", path, a.sid, a.mask)
			} else {
				t.Logf("%s: development ACE for the non-elevated user %s", path, a.sid)
			}
		}
		seen[a.sid] = true
	}
	if !seen[sidSystem] || !seen[sidAdmins] {
		t.Errorf("%s: SYSTEM or Administrators missing: %+v", path, aces)
	}
}

func TestWindowsLiveDataDirACL(t *testing.T) {
	requireLiveWindows(t)
	t.Logf("elevated: %v; production data directory would be %s", fsutil.IsElevated(), ResolvePaths("").StateDir)

	// A parent with a permissive inheritable ACL (Users full control) proves
	// that nothing leaks into the data directory.
	parent := t.TempDir()
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}

	p := ResolvePaths(filepath.Join(parent, "DranzoRMM"))
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	expectSystemAdminsOnly(t, p.StateDir, true)

	// Files written by the agent.
	if err := SaveBootstrap(p, &Bootstrap{ServerURL: "https://rmm.example.com:8443", Token: "dz_enroll_livetest000000"}); err != nil {
		t.Fatal(err)
	}
	if err := Save(p, &Config{ServerURL: "https://rmm.example.com:8443", DeviceID: "dev-live"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveStatus(p, &Status{PID: os.Getpid(), Version: "live"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p.BootstrapFile(), p.ConfigFile(), p.StatusFile()} {
		expectSystemAdminsOnly(t, f, false)
		if err := fsutil.CheckPrivate(f); err != nil {
			t.Errorf("CheckPrivate(%s): %v", f, err)
		}
	}
	if c, err := Load(p); err != nil || c.DeviceID != "dev-live" {
		t.Fatalf("load: %+v %v", c, err)
	}
	if err := EraseToken(p); err != nil {
		t.Fatal(err)
	}
	if b, err := LoadBootstrap(p); err != nil || b.Token != "" {
		t.Fatalf("token not erased: %+v %v", b, err)
	}
	expectSystemAdminsOnly(t, p.BootstrapFile(), false)

	// A directory that already existed with a permissive ACL is tightened.
	loose := filepath.Join(parent, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if prot, aces, _ := readACL(t, loose); prot || len(aces) == 0 {
		t.Logf("pre-existing dir: protected=%v aces=%d", prot, len(aces))
	}
	if err := ResolvePaths(loose).Ensure(); err != nil {
		t.Fatal(err)
	}
	expectSystemAdminsOnly(t, loose, true)

	// A file put there by hand (inheriting the loose ACL of its parent) is refused.
	handmade := filepath.Join(parent, "handmade.json")
	if err := os.WriteFile(handmade, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.CheckPrivate(handmade); err == nil {
		t.Error("CheckPrivate accepted a file that Users can write")
	}

	// icacls, for the human reading the log.
	if out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), p.StateDir).CombinedOutput(); err == nil {
		t.Logf("icacls:\n%s", strings.TrimSpace(string(out)))
	}
}
