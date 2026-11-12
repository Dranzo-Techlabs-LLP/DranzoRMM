// Package fsutil holds the small set of filesystem helpers the agent uses for
// its protected data directory: atomic writes and restrictive permissions
// (0700 directories / 0600 files on Unix; a SYSTEM + Administrators ACL with
// inheritance disabled on Windows).
package fsutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrTooLarge is returned by ReadFileLimited when a file exceeds its limit.
var ErrTooLarge = errors.New("file exceeds size limit")

// EnsurePrivateDir creates dir (and parents) if needed and applies the
// restrictive directory protection to dir itself.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if err := protectDir(dir); err != nil {
		return fmt.Errorf("protect directory %s: %w", dir, err)
	}
	return nil
}

// WriteFileAtomic writes data to path so that readers see either the old or
// the new content, never a partial file. The file is created with restrictive
// permissions before any data is written.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*") // 0600 on Unix
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := protectFile(tmpName); err != nil {
		cleanup()
		return fmt.Errorf("protect %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	syncDir(dir)
	return nil
}

// ReadFileLimited reads at most limit bytes of path and fails with ErrTooLarge
// when the file is bigger, so a corrupted or hostile file cannot exhaust memory.
func ReadFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w", path, ErrTooLarge)
	}
	return data, nil
}

// ReadPrivateFile verifies that path is protected (see CheckPrivate) and then
// reads it with a size limit. It is used for keys and trust anchors.
func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	if err := CheckPrivate(path); err != nil {
		return nil, err
	}
	return ReadFileLimited(path, limit)
}

// Exists reports whether path exists.
func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
