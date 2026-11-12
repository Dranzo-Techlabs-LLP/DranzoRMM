//go:build linux

package userui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// writeTTY writes a notice to a terminal device. O_NOCTTY keeps the agent
// from ever acquiring the terminal as its controlling terminal; O_NONBLOCK
// and the deadline keep a stopped (XOFF) terminal from blocking the agent.
func writeTTY(path, text string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return errors.New("not a terminal device")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_ = f.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = f.WriteString(text)
	return err
}

// createEndFile creates an empty file in the user's runtime directory
// (/run/user/<uid>, writable only by that user). The user ends a session
// announced on a text terminal by removing it. It returns "" when the
// directory does not exist.
func createEndFile(u *platform.User) string {
	uid, err := strconv.Atoi(u.UID)
	if err != nil || uid <= 0 {
		return ""
	}
	dir := "/run/user/" + u.UID
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return ""
	}
	// The directory must really be the user's own: nobody else can then
	// remove the file and end somebody else's support session.
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid || fi.Mode().Perm()&0o022 != 0 {
		return ""
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	path := filepath.Join(dir, endFilePrefix+hex.EncodeToString(b[:]))
	// O_EXCL never follows a symlink planted under that name.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return ""
	}
	_ = f.Close()
	gid, _ := strconv.Atoi(u.GID)
	_ = os.Lchown(path, uid, gid)
	return path
}
