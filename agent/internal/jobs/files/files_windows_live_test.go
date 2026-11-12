//go:build windows

package files

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Live Windows tests (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit): the file browser handlers on NTFS with real
// ACLs and a real junction, all inside a temporary directory.

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

func runningAsSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

func setSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("set ACL of %s: %v", path, err)
	}
}

func sddlOf(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read ACL of %s: %v", path, err)
	}
	return sd.String()
}

func mklinkJunction(t *testing.T, link, target string) {
	t.Helper()
	out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/D", "/C", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
}

func TestWindowsLiveFileJobs(t *testing.T) {
	requireLiveWindows(t)
	e := newEnv(t)
	t.Logf("temp dir %s, running as SYSTEM: %v", e.dir, runningAsSystem())

	// List: files, a subdirectory and a junction.
	e.write("a.txt", "hello", 0o644)
	if err := os.Mkdir(e.path("sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	mklinkJunction(t, e.path("junction"), e.path("sub"))
	res := e.run(List(), e.session, protocol.FileListSpec{Path: e.dir})
	wantStatus(t, res, protocol.StatusSucceeded)
	list := res.Result.(protocol.FileListResult)
	byName := map[string]protocol.FileEntry{}
	for _, en := range list.Entries {
		byName[en.Name] = en
		t.Logf("entry %+v", en)
	}
	if byName["a.txt"].SizeBytes != 5 || byName["a.txt"].IsDir || !byName["sub"].IsDir {
		t.Errorf("list: %+v", list.Entries)
	}
	if _, ok := byName["junction"]; !ok {
		t.Error("junction not listed")
	}
	// Drive root listing works (C:\ as the technician would open it).
	res = e.run(List(), e.session, protocol.FileListSpec{Path: os.Getenv("SystemDrive") + `\`})
	wantStatus(t, res, protocol.StatusSucceeded)
	if n := len(res.Result.(protocol.FileListResult).Entries); n == 0 {
		t.Error("system drive root lists nothing")
	}

	// Read a regular file.
	id := protocol.NewID()
	res = e.run(Read(), e.session, protocol.FileReadSpec{Path: e.path("a.txt"), UploadID: id, MaxBytes: 100})
	wantStatus(t, res, protocol.StatusSucceeded)
	if got := e.blobs.uploads[id]; string(got) != "hello" {
		t.Errorf("uploaded %q", got)
	}
	// A directory and a junction are not files.
	for _, p := range []string{e.path("sub"), e.path("junction")} {
		res = e.run(Read(), e.session, protocol.FileReadSpec{Path: p, UploadID: protocol.NewID(), MaxBytes: 100})
		if res.Status == protocol.StatusSucceeded {
			t.Errorf("read of %s succeeded", p)
		}
	}

	// Write a new file into a directory with an explicit ACL: the new file
	// inherits it (SYSTEM, Administrators, and Users read).
	aclDir := e.path("acl")
	if err := os.Mkdir(aclDir, 0o755); err != nil {
		t.Fatal(err)
	}
	setSDDL(t, aclDir, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
	blob, sum := e.blobs.add([]byte("new content"))
	dst := filepath.Join(aclDir, "new.txt")
	res = e.run(Write(), e.session, protocol.FileWriteSpec{Path: dst, BlobID: blob, SHA256: sum, SizeBytes: 11})
	wantStatus(t, res, protocol.StatusSucceeded)
	if data, _ := os.ReadFile(dst); string(data) != "new content" {
		t.Errorf("written %q", data)
	}
	acl := sddlOf(t, dst)
	t.Logf("ACL of the written file: %s", acl)
	if !strings.Contains(acl, ";;;BU)") {
		t.Errorf("the new file did not inherit the directory's ACL: %s", acl)
	}

	// Existing file without overwrite: refused, content unchanged.
	blob2, sum2 := e.blobs.add([]byte("second"))
	res = e.run(Write(), e.session, protocol.FileWriteSpec{Path: dst, BlobID: blob2, SHA256: sum2, SizeBytes: 6})
	wantStatus(t, res, protocol.StatusRejected)
	// Overwrite: atomic replace, no temporary file left behind.
	res = e.run(Write(), e.session, protocol.FileWriteSpec{Path: dst, BlobID: blob2, SHA256: sum2, SizeBytes: 6, Overwrite: true})
	wantStatus(t, res, protocol.StatusSucceeded)
	if data, _ := os.ReadFile(dst); string(data) != "second" {
		t.Errorf("after overwrite %q", data)
	}
	entries, _ := os.ReadDir(aclDir)
	if len(entries) != 1 {
		t.Errorf("leftovers in %s: %v", aclDir, entries)
	}

	// Replacing a file that is open for reading (with FILE_SHARE_DELETE, as
	// Go opens files) works; one opened without it fails cleanly.
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	blob3, sum3 := e.blobs.add([]byte("third"))
	res = e.run(Write(), e.session, protocol.FileWriteSpec{Path: dst, BlobID: blob3, SHA256: sum3, SizeBytes: 5, Overwrite: true})
	_ = f.Close()
	t.Logf("RESULT overwrite of a file open by another reader (share-delete): %s %q", res.Status, res.Message)

	// Destinations that are not files are refused, with and without overwrite.
	for _, p := range []string{e.path("sub"), e.path("junction")} {
		for _, ow := range []bool{false, true} {
			res = e.run(Write(), e.session, protocol.FileWriteSpec{Path: p, BlobID: blob2, SHA256: sum2, SizeBytes: 6, Overwrite: ow})
			if res.Status != protocol.StatusRejected {
				t.Errorf("write to %s (overwrite=%v): %s %q", p, ow, res.Status, res.Message)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(e.path("sub"), "x")); err == nil {
		t.Error("something was written through the junction")
	}

	// Writing through a junction into its target directory names a regular
	// path and is allowed (the technician is an administrator); it lands in
	// the target.
	res = e.run(Write(), e.session, protocol.FileWriteSpec{Path: filepath.Join(e.path("junction"), "via.txt"), BlobID: blob2, SHA256: sum2, SizeBytes: 6})
	t.Logf("RESULT write through a junction directory: %s %q", res.Status, res.Message)

	// A file only SYSTEM may read: an elevated administrator is denied, the
	// agent (LocalSystem) reads it.
	locked := e.write("locked.txt", "secret", 0o644)
	t.Cleanup(func() { setSDDL(t, locked, "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)") })
	setSDDL(t, locked, "D:PAI(A;;FA;;;SY)")
	res = e.run(Read(), e.session, protocol.FileReadSpec{Path: locked, UploadID: protocol.NewID(), MaxBytes: 100})
	t.Logf("read of a SYSTEM-only file: %s %q", res.Status, res.Message)
	if runningAsSystem() {
		wantStatus(t, res, protocol.StatusSucceeded)
	} else if res.Status != protocol.StatusFailed || !strings.Contains(strings.ToLower(res.Message), "denied") {
		t.Errorf("read of a SYSTEM-only file as an administrator: %s %q", res.Status, res.Message)
	}

	// A device path is refused before anything is opened.
	res = e.run(Read(), e.session, protocol.FileReadSpec{Path: `\\.\PhysicalDrive0`, UploadID: protocol.NewID(), MaxBytes: 100})
	wantStatus(t, res, protocol.StatusRejected)
}

// TestWindowsLiveRenameNoReplace checks the MoveFileEx error mapping.
func TestWindowsLiveRenameNoReplace(t *testing.T) {
	requireLiveWindows(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(a, b); err != os.ErrExist { //nolint:errorlint // renameNoReplace returns the sentinel itself
		t.Fatalf("rename onto an existing file: %v", err)
	}
	if data, _ := os.ReadFile(b); !bytes.Equal(data, []byte("b")) {
		t.Fatal("destination changed")
	}
	c := filepath.Join(dir, "c")
	if err := renameNoReplace(a, c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a); !os.IsNotExist(err) {
		t.Fatal("source still exists")
	}
}
