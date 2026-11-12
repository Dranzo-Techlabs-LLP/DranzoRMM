//go:build !windows

package files

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// specialFiles creates one of each non-regular file kind that can be made
// without privileges and adds a character device.
func specialFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{"character device": "/dev/null"}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	out["FIFO"] = fifo
	// Unix socket paths are short: use a short temp directory.
	sockDir, err := os.MkdirTemp("", "dz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	out["socket"] = sock
	return out
}

func TestOverwriteKeepsOwnerAndDropsSetuid(t *testing.T) {
	e := newEnv(t)
	p := e.write("tool", "old", 0o755)
	if err := os.Chmod(p, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(p, 12345, 23456); err != nil {
			t.Fatal(err)
		}
	}
	r := e.run(Write(), e.session, e.writeSpec("tool", []byte("new"), true))
	wantStatus(t, r, protocol.StatusSucceeded)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSetuid != 0 {
		t.Errorf("mode = %v, want 0755 without set-uid", fi.Mode())
	}
	if os.Geteuid() == 0 {
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != 12345 || st.Gid != 23456 {
			t.Errorf("owner = %d:%d, want 12345:23456", st.Uid, st.Gid)
		}
	}
}

func TestReadPseudoFile(t *testing.T) {
	// Kernel pseudo-files report size 0 but have content.
	const p = "/proc/version"
	if fi, err := os.Stat(p); err != nil || fi.Size() != 0 {
		t.Skip("no /proc on this system")
	}
	e := newEnv(t)
	upload := protocol.NewID()
	r := e.run(Read(), e.session, protocol.FileReadSpec{Path: p, UploadID: upload, MaxBytes: 1 << 20})
	wantStatus(t, r, protocol.StatusSucceeded)
	if res := r.Result.(protocol.FileReadResult); res.SizeBytes == 0 || int64(len(e.blobs.uploads[upload])) != res.SizeBytes {
		t.Errorf("result = %+v, uploaded %d bytes", res, len(e.blobs.uploads[upload]))
	}
}
