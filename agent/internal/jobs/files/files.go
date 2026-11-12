// Package files implements the file browser job kinds file.list, file.read
// and file.write (docs/PROTOCOL.md section 6.2).
//
// Every job must belong to an ACTIVE "files" session: that session is what
// obtained the user's consent (where required) and what keeps the visible
// "remote session active" indicator on screen while files are transferred.
// Without it the job is rejected.
//
// The agent runs as root / LocalSystem and this is an administrator's tool:
// paths are used as given by the technician and are not confined to a
// directory. What the handlers do enforce is that a path is well formed, that
// only regular files are read, that sizes are bounded and that a write either
// lands completely and verified or not at all.
package files

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

// Limits.
const (
	// MaxPathBytes is the longest accepted path.
	MaxPathBytes = 4096
	// MaxListEntries is the largest number of entries in a file.list result.
	MaxListEntries = 5000
	// MaxTransferBytes bounds file.read and file.write (4 GiB).
	MaxTransferBytes = 4 << 30
	// maxListResultBytes keeps a file.list result well below the 2 MiB
	// message limit even when names are long.
	maxListResultBytes = 1200 << 10
	// maxUnsizedBytes bounds reading files that report size 0 but have
	// content (/proc, /sys).
	maxUnsizedBytes = 1 << 20
)

// ValidatePath checks a path from a job spec and returns it cleaned: it must
// be absolute for this OS, contain no NUL and be at most MaxPathBytes long.
func ValidatePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("path is empty")
	}
	if len(p) > MaxPathBytes {
		return "", fmt.Errorf("path exceeds %d bytes", MaxPathBytes)
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains a NUL character")
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	if err := checkOSPath(p); err != nil {
		return "", err
	}
	return filepath.Clean(p), nil
}

// requireSession rejects a job that does not belong to an active files session.
func requireSession(jc *jobs.JobContext) *jobs.Result {
	reject := func(msg string) *jobs.Result {
		r := jobs.Rejected("%s", msg)
		return &r
	}
	if jc.SessionID == "" || !protocol.ValidUUID(jc.SessionID) {
		return reject("file jobs need the sessionId of an active files session")
	}
	if jc.Sessions == nil {
		return reject("no active files session")
	}
	kind, ok := jc.Sessions.ActiveSession(jc.SessionID)
	if !ok {
		return reject("no active files session")
	}
	if kind != protocol.SessionKindFiles {
		return reject("the session is not a files session")
	}
	return nil
}

func logger(jc *jobs.JobContext) *slog.Logger {
	if jc.Log != nil {
		return jc.Log
	}
	return slog.New(slog.DiscardHandler)
}

// describe turns an OS error into a short message without repeating the
// path (the dashboard already knows it).
func describe(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err.Error()
	}
	return err.Error()
}

// ---- file.list ----

// List returns the handler of file.list.
func List() jobs.Handler { return jobs.HandlerFunc(handleList) }

func handleList(jc *jobs.JobContext) jobs.Result {
	if r := requireSession(jc); r != nil {
		return *r
	}
	var spec protocol.FileListSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	path, err := ValidatePath(spec.Path)
	if err != nil {
		return jobs.Rejected("%v", err)
	}
	logger(jc).Info("file.list", slog.String("path", path), slog.String("session_id", jc.SessionID))

	dir, err := os.Open(path)
	if err != nil {
		return jobs.Failed("cannot open directory: %s", describe(err))
	}
	defer func() { _ = dir.Close() }()
	if fi, err := dir.Stat(); err != nil {
		return jobs.Failed("cannot read directory: %s", describe(err))
	} else if !fi.IsDir() {
		return jobs.Failed("not a directory")
	}

	result := protocol.FileListResult{Path: path, Entries: []protocol.FileEntry{}}
	budget := maxListResultBytes
	for !result.Truncated {
		if jc.Ctx.Err() != nil {
			return jobs.Failed("cancelled")
		}
		batch, rerr := dir.ReadDir(256)
		for _, de := range batch {
			if len(result.Entries) >= MaxListEntries {
				result.Truncated = true
				break
			}
			entry := protocol.FileEntry{Name: de.Name(), IsDir: de.IsDir(), Mode: de.Type().String()}
			// Info is lstat: a symbolic link is described, never followed.
			if fi, ierr := de.Info(); ierr == nil {
				entry.IsDir = fi.IsDir()
				entry.SizeBytes = fi.Size()
				entry.ModifiedAt = fi.ModTime().UTC()
				entry.Mode = fi.Mode().String()
			}
			encoded, _ := json.Marshal(entry)
			if budget -= len(encoded) + 1; budget < 0 {
				result.Truncated = true
				break
			}
			result.Entries = append(result.Entries, entry)
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) && len(result.Entries) == 0 {
				return jobs.Failed("cannot read directory: %s", describe(rerr))
			}
			break
		}
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].Name < result.Entries[j].Name })
	return jobs.SucceededWith(result)
}

// ---- file.read ----

// Read returns the handler of file.read.
func Read() jobs.Handler { return jobs.HandlerFunc(handleRead) }

func handleRead(jc *jobs.JobContext) jobs.Result {
	if r := requireSession(jc); r != nil {
		return *r
	}
	var spec protocol.FileReadSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	path, err := ValidatePath(spec.Path)
	if err != nil {
		return jobs.Rejected("%v", err)
	}
	if !protocol.ValidUUID(spec.UploadID) {
		return jobs.Rejected("invalid uploadId")
	}
	if spec.MaxBytes <= 0 || spec.MaxBytes > MaxTransferBytes {
		return jobs.Rejected("maxBytes must be between 1 and %d", int64(MaxTransferBytes))
	}
	if jc.Blobs == nil {
		return jobs.Failed("uploads are not available")
	}
	logger(jc).Info("file.read", slog.String("path", path), slog.String("session_id", jc.SessionID))

	// Only regular files: a device, FIFO or socket could block forever or
	// return endless data. The check is repeated on the opened file, so the
	// path cannot be swapped in between.
	fi, err := os.Stat(path)
	if err != nil {
		return jobs.Failed("cannot read file: %s", describe(err))
	}
	if !fi.Mode().IsRegular() {
		return jobs.Rejected("not a regular file")
	}
	f, err := openForRead(path)
	if err != nil {
		return jobs.Failed("cannot open file: %s", describe(err))
	}
	defer func() { _ = f.Close() }()
	fi, err = f.Stat()
	if err != nil {
		return jobs.Failed("cannot read file: %s", describe(err))
	}
	if !fi.Mode().IsRegular() {
		return jobs.Rejected("not a regular file")
	}
	size := fi.Size()
	if size > spec.MaxBytes {
		// Refuse rather than hand over a silently truncated file.
		return jobs.Rejected("file is %d bytes, larger than the limit of %d bytes", size, spec.MaxBytes)
	}

	var src io.Reader = f
	if size == 0 {
		// Kernel pseudo-files report size 0: read them into memory, bounded.
		limit := min(spec.MaxBytes, int64(maxUnsizedBytes))
		data, rerr := io.ReadAll(io.LimitReader(f, limit+1))
		if rerr != nil {
			return jobs.Failed("cannot read file: %s", describe(rerr))
		}
		if int64(len(data)) > limit {
			return jobs.Rejected("file is larger than the limit of %d bytes", limit)
		}
		size = int64(len(data))
		src = strings.NewReader(string(data))
	}

	// The session may have ended while the job was queued or reading.
	if r := requireSession(jc); r != nil {
		return *r
	}
	h := sha256.New()
	counter := &countingReader{r: io.TeeReader(io.LimitReader(src, size), h)}
	if err := jc.Blobs.Upload(jc.Ctx, spec.UploadID, counter, size); err != nil {
		return jobs.Failed("upload failed: %v", err)
	}
	if counter.n != size {
		// The file shrank while it was being read.
		return jobs.Failed("file changed while it was being read")
	}
	return jobs.SucceededWith(protocol.FileReadResult{SizeBytes: size, SHA256: hex.EncodeToString(h.Sum(nil))})
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ---- file.write ----

// Write returns the handler of file.write.
func Write() jobs.Handler { return jobs.HandlerFunc(handleWrite) }

func handleWrite(jc *jobs.JobContext) jobs.Result {
	if r := requireSession(jc); r != nil {
		return *r
	}
	var spec protocol.FileWriteSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	path, err := ValidatePath(spec.Path)
	if err != nil {
		return jobs.Rejected("%v", err)
	}
	if !protocol.ValidUUID(spec.BlobID) {
		return jobs.Rejected("invalid blobId")
	}
	if !protocol.ValidSHA256Hex(spec.SHA256) {
		return jobs.Rejected("invalid sha256")
	}
	if spec.SizeBytes < 0 || spec.SizeBytes > MaxTransferBytes {
		return jobs.Rejected("sizeBytes must be between 0 and %d", int64(MaxTransferBytes))
	}
	if jc.Blobs == nil {
		return jobs.Failed("downloads are not available")
	}
	dir, base := filepath.Split(path)
	if base == "" || dir == "" {
		return jobs.Rejected("path does not name a file")
	}
	logger(jc).Info("file.write", slog.String("path", path), slog.String("sha256", spec.SHA256),
		slog.Int64("size_bytes", spec.SizeBytes), slog.Bool("overwrite", spec.Overwrite), slog.String("session_id", jc.SessionID))

	// What is at the destination now? Lstat: a symbolic link is never followed.
	existing, lerr := os.Lstat(path)
	switch {
	case lerr == nil:
		if msg := refuseDestination(existing, spec.Overwrite); msg != "" {
			return jobs.Rejected("%s", msg)
		}
	case errors.Is(lerr, os.ErrNotExist):
		existing = nil
	default:
		return jobs.Failed("cannot check the destination: %s", describe(lerr))
	}
	if di, derr := os.Stat(dir); derr != nil {
		return jobs.Failed("cannot write to the destination directory: %s", describe(derr))
	} else if !di.IsDir() {
		return jobs.Failed("the destination directory is not a directory")
	}

	// Download next to the destination (same file system, so the final
	// rename is atomic) into a new owner-only file. The blob client verifies
	// size and SHA-256 and removes the file on any mismatch.
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return jobs.Failed("cannot create a temporary file name")
	}
	tmp := filepath.Join(dir, ".dranzo-upload-"+hex.EncodeToString(rnd[:])+".tmp")
	if err := jc.Blobs.DownloadFile(jc.Ctx, spec.BlobID, tmp, spec.SizeBytes, spec.SHA256); err != nil {
		_ = os.Remove(tmp)
		if isIntegrityError(err) {
			return jobs.Rejected("download refused: %v", err)
		}
		return jobs.Failed("download failed: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	// Belt and braces: the file on disk has exactly the signed size.
	if ti, err := os.Lstat(tmp); err != nil || !ti.Mode().IsRegular() || ti.Size() != spec.SizeBytes {
		return jobs.Failed("downloaded file is not what was requested")
	}

	// The session may have ended during the download.
	if r := requireSession(jc); r != nil {
		return *r
	}

	if existing == nil {
		// New file: conservative permissions (owner only; on Windows the
		// directory's inherited ACL). Fails if something appeared meanwhile.
		if err := renameNoReplace(tmp, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return jobs.Rejected("the destination already exists (overwrite was not requested)")
			}
			return jobs.Failed("cannot create the file: %s", describe(err))
		}
		committed = true
		return jobs.SucceededWith(protocol.FileWriteResult{SizeBytes: spec.SizeBytes})
	}

	// Overwrite: check again right before the rename, keep the existing
	// file's owner and permission bits (replacing /etc/hosts must not turn it
	// into a root-only file), then replace atomically. Renaming over a
	// symbolic link would replace the link itself, never its target.
	current, err := os.Lstat(path)
	if err != nil {
		return jobs.Failed("cannot check the destination: %s", describe(err))
	}
	if msg := refuseDestination(current, true); msg != "" {
		return jobs.Rejected("%s", msg)
	}
	if err := copyOwnerAndMode(tmp, current); err != nil {
		return jobs.Failed("cannot keep the permissions of the existing file: %s", describe(err))
	}
	if err := os.Rename(tmp, path); err != nil {
		return jobs.Failed("cannot replace the file: %s", describe(err))
	}
	committed = true
	return jobs.SucceededWith(protocol.FileWriteResult{SizeBytes: spec.SizeBytes})
}

// refuseDestination says why an existing destination must not be written
// ("" when it may be replaced).
func refuseDestination(fi os.FileInfo, overwrite bool) string {
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return "the destination is a symbolic link"
	case fi.IsDir():
		return "the destination is a directory"
	case !fi.Mode().IsRegular():
		return "the destination is not a regular file"
	case !overwrite:
		return "the destination already exists (overwrite was not requested)"
	}
	return ""
}

// isIntegrityError recognises a download whose content is not what the
// signed command described.
func isIntegrityError(err error) bool {
	return errors.Is(err, transport.ErrHashMismatch) || errors.Is(err, transport.ErrSizeMismatch)
}
