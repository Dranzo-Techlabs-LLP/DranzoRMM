package update

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// exePaths names the executable and the files kept next to it.
type exePaths struct {
	exe string
}

// previous is the binary that ran before the last update. It is kept after a
// successful update for manual recovery.
func (p exePaths) previous() string { return p.exe + ".previous" }

// previousTmp is the scratch name used to replace previous atomically.
func (p exePaths) previousTmp() string { return p.exe + ".previous.tmp" }

// staged is the verified new binary just before the exchange. On Windows the
// ".exe" extension is kept so the file can be started for the version probe.
func (p exePaths) staged() string {
	ext := filepath.Ext(p.exe)
	if strings.EqualFold(ext, ".exe") {
		return strings.TrimSuffix(p.exe, ext) + ".new" + ext
	}
	return p.exe + ".new"
}

// rollbackTmp is the scratch copy of previous that is renamed over exe.
func (p exePaths) rollbackTmp() string { return p.exe + ".rollback.tmp" }

// failedAside is where a failed binary that is still running is moved during
// a rollback on Windows (a running image can be renamed but not replaced).
func (p exePaths) failedAside() string { return p.exe + ".failed" }

// scratch lists the files that are only meaningful while an operation runs
// and may be deleted whenever no operation is in flight.
func (p exePaths) scratch() []string {
	return []string{p.staged(), p.previousTmp(), p.rollbackTmp(), p.failedAside()}
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// copyFile copies src to a NEW file dst (an existing dst is removed first),
// flushes it to stable storage and returns the SHA-256 and size of the bytes
// written. The file is created owner-only; the caller sets the final mode.
func copyFile(src, dst string) (sum []byte, n int64, err error) {
	in, err := os.Open(src)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = in.Close() }()
	if err := removeIfExists(dst); err != nil {
		return nil, 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, 0, err
	}
	h := sha256.New()
	n, err = io.Copy(io.MultiWriter(out, h), in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		return nil, 0, fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	return h.Sum(nil), n, nil
}

// copyVerified copies the downloaded file to dst and proves that the bytes
// that reached dst are exactly the binary named by the signed command.
func copyVerified(src, dst, sha256Hex string, sizeBytes int64) error {
	want, err := hex.DecodeString(sha256Hex)
	if err != nil || len(want) != sha256.Size {
		return errors.New("invalid sha256")
	}
	sum, n, err := copyFile(src, dst)
	if err != nil {
		return err
	}
	if n != sizeBytes || subtle.ConstantTimeCompare(sum, want) != 1 {
		_ = os.Remove(dst)
		return errors.New("staged binary does not match the signed size and SHA-256")
	}
	return nil
}

// duplicate makes dst a second name for (hard link) or a durable copy of
// src, with src's owner and mode. dst is replaced if it exists.
func duplicate(src, dst string) error {
	if err := removeIfExists(dst); err != nil {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	// Hard links can be unavailable (file system, policy): copy instead.
	if _, _, err := copyFile(src, dst); err != nil {
		return err
	}
	if err := matchOwnerAndMode(dst, src); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return syncFile(dst)
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// fileOps performs the two exchanges of the executable. renameAside selects
// the strategy:
//
//   - false (Unix): rename(2) replaces the destination atomically even while
//     it is running, so the executable path names a complete binary at every
//     instant: the old one before the rename, the new one after.
//   - true (Windows): a running image cannot be replaced or deleted, only
//     renamed. The running executable is renamed aside and the new file is
//     renamed into place. Between the two renames the executable path does
//     not exist (see the interruption table in updater.go).
type fileOps struct {
	paths       exePaths
	renameAside bool
	// fp is a test hook called at every interruption point (nil in production).
	fp func(point string)
}

func (o fileOps) point(name string) {
	if o.fp != nil {
		o.fp(name)
	}
}

// exchange installs the staged binary at the executable path and keeps the
// binary that was there as <exe>.previous (replacing an older one). On error
// the executable path still names the old binary.
func (o fileOps) exchange() error {
	p := o.paths
	dir := filepath.Dir(p.exe)
	if o.renameAside {
		if err := os.Rename(p.exe, p.previous()); err != nil {
			return fmt.Errorf("move the running executable aside: %w", err)
		}
		o.point("swap:moved-aside")
		if err := os.Rename(p.staged(), p.exe); err != nil {
			// Put the old binary back; if even that fails the caller reports
			// the error and <exe>.previous still holds the old binary.
			if rerr := os.Rename(p.previous(), p.exe); rerr != nil {
				return fmt.Errorf("install the new executable: %w (restoring the old one also failed: %w)", err, rerr)
			}
			return fmt.Errorf("install the new executable: %w", err)
		}
		syncDir(dir)
		return nil
	}
	if err := duplicate(p.exe, p.previousTmp()); err != nil {
		return fmt.Errorf("keep the current executable: %w", err)
	}
	if err := os.Rename(p.previousTmp(), p.previous()); err != nil {
		_ = os.Remove(p.previousTmp())
		return fmt.Errorf("keep the current executable: %w", err)
	}
	syncDir(dir)
	o.point("swap:previous-kept")
	if err := os.Rename(p.staged(), p.exe); err != nil {
		return fmt.Errorf("install the new executable: %w", err)
	}
	syncDir(dir)
	return nil
}

// restore puts <exe>.previous back at the executable path. <exe>.previous is
// kept. On error the executable path still names the binary it named before.
func (o fileOps) restore() error {
	p := o.paths
	dir := filepath.Dir(p.exe)
	if err := duplicate(p.previous(), p.rollbackTmp()); err != nil {
		return fmt.Errorf("prepare the previous executable: %w", err)
	}
	if o.renameAside {
		if err := os.Rename(p.exe, p.failedAside()); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(p.rollbackTmp())
			return fmt.Errorf("move the failed executable aside: %w", err)
		}
		o.point("rollback:moved-aside")
		if err := os.Rename(p.rollbackTmp(), p.exe); err != nil {
			if rerr := os.Rename(p.failedAside(), p.exe); rerr != nil {
				return fmt.Errorf("restore the previous executable: %w (putting the failed one back also failed: %w)", err, rerr)
			}
			_ = os.Remove(p.rollbackTmp())
			return fmt.Errorf("restore the previous executable: %w", err)
		}
		syncDir(dir)
		return nil
	}
	if err := os.Rename(p.rollbackTmp(), p.exe); err != nil {
		_ = os.Remove(p.rollbackTmp())
		return fmt.Errorf("restore the previous executable: %w", err)
	}
	syncDir(dir)
	return nil
}
