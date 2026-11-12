package files

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

// sessions is a jobs.SessionLookup with a fixed set of active sessions.
type sessions struct {
	mu     sync.Mutex
	active map[string]string
}

func (s *sessions) ActiveSession(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kind, ok := s.active[id]
	return kind, ok
}

func (s *sessions) end(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, id)
}

// blobs is a jobs.BlobClient that behaves like the real one: DownloadFile
// creates the file exclusively, verifies size and hash and removes the file
// on a mismatch.
type blobs struct {
	mu        sync.Mutex
	content   map[string][]byte
	uploads   map[string][]byte
	downloads int
	// leaveBad keeps a mismatching download on disk (a misbehaving client).
	leaveBad bool
	// duringDownload runs after the temporary file was written.
	duringDownload func(tmpPath string)
	uploadErr      error
}

func newBlobs() *blobs { return &blobs{content: map[string][]byte{}, uploads: map[string][]byte{}} }

func (b *blobs) add(data []byte) (id, sum string) {
	id = protocol.NewID()
	h := sha256.Sum256(data)
	b.mu.Lock()
	b.content[id] = data
	b.mu.Unlock()
	return id, hex.EncodeToString(h[:])
}

func (b *blobs) Download(_ context.Context, blobID string, dst io.Writer, sizeBytes int64, sha256Hex string) error {
	b.mu.Lock()
	data, ok := b.content[blobID]
	b.downloads++
	b.mu.Unlock()
	if !ok {
		return errors.New("download blob: HTTP status 404")
	}
	if _, err := dst.Write(data); err != nil {
		return err
	}
	if int64(len(data)) != sizeBytes {
		return transport.ErrSizeMismatch
	}
	if h := sha256.Sum256(data); hex.EncodeToString(h[:]) != sha256Hex {
		return transport.ErrHashMismatch
	}
	return nil
}

func (b *blobs) DownloadFile(ctx context.Context, blobID, destPath string, sizeBytes int64, sha256Hex string) error {
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create download file: %w", err)
	}
	err = b.Download(ctx, blobID, f, sizeBytes, sha256Hex)
	_ = f.Close()
	if err != nil && !b.leaveBad {
		_ = os.Remove(destPath)
	}
	if err == nil && b.duringDownload != nil {
		b.duringDownload(destPath)
	}
	return err
}

func (b *blobs) Upload(_ context.Context, uploadID string, src io.Reader, sizeBytes int64) error {
	if b.uploadErr != nil {
		return b.uploadErr
	}
	data, err := io.ReadAll(io.LimitReader(src, sizeBytes))
	if err != nil {
		return err
	}
	if int64(len(data)) != sizeBytes {
		return errors.New("upload: short body")
	}
	b.mu.Lock()
	b.uploads[uploadID] = data
	b.mu.Unlock()
	return nil
}

type env struct {
	t        *testing.T
	sessions *sessions
	blobs    *blobs
	session  string
	dir      string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	id := protocol.NewID()
	dir := t.TempDir()
	// macOS temp directories live behind a symlink (/var -> /private/var).
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	return &env{t: t, sessions: &sessions{active: map[string]string{id: protocol.SessionKindFiles}}, blobs: newBlobs(), session: id, dir: dir}
}

func (e *env) run(h jobs.Handler, sessionID string, spec any) jobs.Result {
	e.t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		e.t.Fatal(err)
	}
	return h.Handle(&jobs.JobContext{
		Ctx: context.Background(), DeviceID: protocol.NewID(), JobRunID: protocol.NewID(),
		Spec: raw, SessionID: sessionID, Blobs: e.blobs, Sessions: e.sessions, TempDir: e.t.TempDir(),
	})
}

func (e *env) path(name string) string { return filepath.Join(e.dir, name) }

func (e *env) write(name, content string, mode os.FileMode) string {
	e.t.Helper()
	p := e.path(name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *env) names() []string {
	e.t.Helper()
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, de := range entries {
		out = append(out, de.Name())
	}
	return out
}

func wantStatus(t *testing.T, r jobs.Result, status string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %s (%s), want %s", r.Status, r.Message, status)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks need a privilege on Windows: %v", err)
		}
		t.Fatal(err)
	}
}

// ---- session requirement ----

func TestFileJobsNeedAnActiveFilesSession(t *testing.T) {
	e := newEnv(t)
	e.write("secret.txt", "secret", 0o600)
	terminal := protocol.NewID()
	e.sessions.active[terminal] = protocol.SessionKindTerminal
	desktop := protocol.NewID()
	e.sessions.active[desktop] = protocol.SessionKindDesktop
	blobID, sum := e.blobs.add([]byte("new"))

	specs := map[string]struct {
		h    jobs.Handler
		spec any
	}{
		"list":  {List(), protocol.FileListSpec{Path: e.dir}},
		"read":  {Read(), protocol.FileReadSpec{Path: e.path("secret.txt"), UploadID: protocol.NewID(), MaxBytes: 100}},
		"write": {Write(), protocol.FileWriteSpec{Path: e.path("new.txt"), BlobID: blobID, SHA256: sum, SizeBytes: 3}},
	}
	for name, c := range specs {
		for why, sessionID := range map[string]string{
			"no session id":     "",
			"unknown session":   protocol.NewID(),
			"terminal session":  terminal,
			"desktop session":   desktop,
			"malformed session": "not-a-uuid",
		} {
			r := e.run(c.h, sessionID, c.spec)
			if r.Status != protocol.StatusRejected {
				t.Errorf("%s with %s: status = %s (%s)", name, why, r.Status, r.Message)
			}
		}
	}
	// A session that has ended no longer authorises anything.
	e.sessions.end(e.session)
	for name, c := range specs {
		if r := e.run(c.h, e.session, c.spec); r.Status != protocol.StatusRejected {
			t.Errorf("%s after the session ended: %s", name, r.Status)
		}
	}
	if len(e.blobs.uploads) != 0 || e.blobs.downloads != 0 {
		t.Errorf("transfers happened without a session: uploads=%d downloads=%d", len(e.blobs.uploads), e.blobs.downloads)
	}
	if got := strings.Join(e.names(), ","); got != "secret.txt" {
		t.Errorf("directory changed: %s", got)
	}
}

func TestPathValidation(t *testing.T) {
	e := newEnv(t)
	bad := []string{"", "relative/path", "./x", "..", "file.txt", e.dir + "\x00/etc/passwd", "/" + strings.Repeat("a", MaxPathBytes)}
	for _, p := range bad {
		for name, r := range map[string]jobs.Result{
			"list":  e.run(List(), e.session, protocol.FileListSpec{Path: p}),
			"read":  e.run(Read(), e.session, protocol.FileReadSpec{Path: p, UploadID: protocol.NewID(), MaxBytes: 1}),
			"write": e.run(Write(), e.session, protocol.FileWriteSpec{Path: p, BlobID: protocol.NewID(), SHA256: strings.Repeat("a", 64)}),
		} {
			if r.Status != protocol.StatusRejected {
				t.Errorf("%s %q: status = %s (%s)", name, p, r.Status, r.Message)
			}
		}
	}
	// A path is cleaned, not rejected, when it merely is not in canonical form.
	got, err := ValidatePath(e.dir + string(filepath.Separator) + "a" + string(filepath.Separator) + ".." + string(filepath.Separator) + "b")
	if err != nil || got != filepath.Join(e.dir, "b") {
		t.Errorf("ValidatePath = %q, %v", got, err)
	}
	if r := e.run(Write(), e.session, map[string]any{"path": e.path("x"), "blobId": "nope", "sha256": "zz", "sizeBytes": -1}); r.Status != protocol.StatusRejected {
		t.Errorf("invalid write spec: %s", r.Status)
	}
	if r := e.run(Read(), e.session, protocol.FileReadSpec{Path: e.path("x"), UploadID: "nope", MaxBytes: 1}); r.Status != protocol.StatusRejected {
		t.Errorf("invalid uploadId: %s", r.Status)
	}
	for _, max := range []int64{0, -5, MaxTransferBytes + 1} {
		if r := e.run(Read(), e.session, protocol.FileReadSpec{Path: e.path("x"), UploadID: protocol.NewID(), MaxBytes: max}); r.Status != protocol.StatusRejected {
			t.Errorf("maxBytes %d: %s", max, r.Status)
		}
	}
}

// ---- file.list ----

func listResult(t *testing.T, r jobs.Result) protocol.FileListResult {
	t.Helper()
	wantStatus(t, r, protocol.StatusSucceeded)
	res, ok := r.Result.(protocol.FileListResult)
	if !ok {
		t.Fatalf("result type %T", r.Result)
	}
	return res
}

func TestList(t *testing.T) {
	e := newEnv(t)
	e.write("b.txt", "hello", 0o640)
	e.write("a.log", strings.Repeat("x", 1234), 0o600)
	if err := os.Mkdir(e.path("sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "big"), make([]byte, 99999), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink(t, filepath.Join(outside, "big"), e.path("link-to-file"))
	symlink(t, outside, e.path("link-to-dir"))
	symlink(t, e.path("does-not-exist"), e.path("dangling"))

	res := listResult(t, e.run(List(), e.session, protocol.FileListSpec{Path: e.dir + string(filepath.Separator)}))
	if res.Path != e.dir || res.Truncated {
		t.Errorf("path = %q truncated = %v", res.Path, res.Truncated)
	}
	byName := map[string]protocol.FileEntry{}
	var order []string
	for _, en := range res.Entries {
		byName[en.Name] = en
		order = append(order, en.Name)
	}
	if got := strings.Join(order, ","); got != "a.log,b.txt,dangling,link-to-dir,link-to-file,sub" {
		t.Errorf("entries = %s", got)
	}
	if en := byName["a.log"]; en.IsDir || en.SizeBytes != 1234 || en.Mode != "-rw-------" || time.Since(en.ModifiedAt) > time.Hour || en.ModifiedAt.Location() != time.UTC {
		t.Errorf("a.log = %+v", en)
	}
	if en := byName["b.txt"]; en.SizeBytes != 5 || en.Mode != "-rw-r-----" {
		t.Errorf("b.txt = %+v", en)
	}
	if en := byName["sub"]; !en.IsDir || !strings.HasPrefix(en.Mode, "d") {
		t.Errorf("sub = %+v", en)
	}
	// Symbolic links are described as links: not as the directory or the
	// 99999 byte file they point to.
	for _, name := range []string{"link-to-file", "link-to-dir", "dangling"} {
		en := byName[name]
		if en.IsDir || !strings.HasPrefix(en.Mode, "L") || en.SizeBytes == 99999 {
			t.Errorf("%s was followed: %+v", name, en)
		}
	}

	// Listing through a symlinked path works (the technician asked for it).
	res = listResult(t, e.run(List(), e.session, protocol.FileListSpec{Path: e.path("link-to-dir")}))
	if len(res.Entries) != 1 || res.Entries[0].Name != "big" {
		t.Errorf("via link: %+v", res.Entries)
	}

	if r := e.run(List(), e.session, protocol.FileListSpec{Path: e.path("b.txt")}); r.Status != protocol.StatusFailed {
		t.Errorf("listing a file: %s", r.Status)
	}
	if r := e.run(List(), e.session, protocol.FileListSpec{Path: e.path("missing")}); r.Status != protocol.StatusFailed || strings.Contains(r.Message, e.dir) {
		t.Errorf("listing a missing directory: %s %q", r.Status, r.Message)
	}
	empty := listResult(t, e.run(List(), e.session, protocol.FileListSpec{Path: e.path("sub")}))
	if raw, _ := json.Marshal(empty); !strings.Contains(string(raw), `"entries":[]`) {
		t.Errorf("empty directory must encode entries as []: %s", raw)
	}
}

func TestListCapsEntries(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < MaxListEntries+25; i++ {
		if err := os.WriteFile(e.path(fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res := listResult(t, e.run(List(), e.session, protocol.FileListSpec{Path: e.dir}))
	if len(res.Entries) != MaxListEntries || !res.Truncated {
		t.Errorf("entries = %d truncated = %v", len(res.Entries), res.Truncated)
	}
	raw, _ := json.Marshal(res)
	if len(raw) > protocol.MaxMessageBytes/2 {
		t.Errorf("result is %d bytes", len(raw))
	}
}

func TestListStaysBelowTheMessageLimit(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("é", 120) // 240 bytes per name
	for i := 0; i < MaxListEntries; i++ {
		if err := os.WriteFile(e.path(fmt.Sprintf("%s%04d", long, i)), nil, 0o600); err != nil {
			t.Skipf("file system does not take long names: %v", err)
		}
	}
	res := listResult(t, e.run(List(), e.session, protocol.FileListSpec{Path: e.dir}))
	raw, _ := json.Marshal(res)
	if !res.Truncated || len(raw) > protocol.MaxMessageBytes*3/4 {
		t.Errorf("entries = %d truncated = %v bytes = %d", len(res.Entries), res.Truncated, len(raw))
	}
}

// ---- file.read ----

func TestRead(t *testing.T) {
	e := newEnv(t)
	content := bytes.Repeat([]byte("dranzo\n"), 20000) // 140 KB
	p := e.path("data.bin")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	upload := protocol.NewID()
	r := e.run(Read(), e.session, protocol.FileReadSpec{Path: p, UploadID: upload, MaxBytes: int64(len(content))})
	wantStatus(t, r, protocol.StatusSucceeded)
	res := r.Result.(protocol.FileReadResult)
	sum := sha256.Sum256(content)
	if res.SizeBytes != int64(len(content)) || res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("result = %+v", res)
	}
	if !bytes.Equal(e.blobs.uploads[upload], content) {
		t.Error("uploaded bytes differ from the file")
	}

	// One byte over the limit: refused, nothing uploaded (never truncated).
	upload = protocol.NewID()
	r = e.run(Read(), e.session, protocol.FileReadSpec{Path: p, UploadID: upload, MaxBytes: int64(len(content)) - 1})
	wantStatus(t, r, protocol.StatusRejected)
	if _, ok := e.blobs.uploads[upload]; ok {
		t.Error("an oversized file was uploaded")
	}

	// Empty file.
	e.write("empty", "", 0o600)
	upload = protocol.NewID()
	r = e.run(Read(), e.session, protocol.FileReadSpec{Path: e.path("empty"), UploadID: upload, MaxBytes: 10})
	wantStatus(t, r, protocol.StatusSucceeded)
	if res := r.Result.(protocol.FileReadResult); res.SizeBytes != 0 || res.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty file: %+v", res)
	}

	// Reading through a symbolic link to a regular file is allowed.
	symlink(t, p, e.path("link"))
	r = e.run(Read(), e.session, protocol.FileReadSpec{Path: e.path("link"), UploadID: protocol.NewID(), MaxBytes: 1 << 20})
	wantStatus(t, r, protocol.StatusSucceeded)

	if r := e.run(Read(), e.session, protocol.FileReadSpec{Path: e.path("missing"), UploadID: protocol.NewID(), MaxBytes: 10}); r.Status != protocol.StatusFailed {
		t.Errorf("missing file: %s", r.Status)
	}
	e.blobs.uploadErr = errors.New("upload: HTTP status 403")
	if r := e.run(Read(), e.session, protocol.FileReadSpec{Path: p, UploadID: protocol.NewID(), MaxBytes: 1 << 20}); r.Status != protocol.StatusFailed {
		t.Errorf("failed upload: %s", r.Status)
	}
}

func TestReadRefusesNonRegularFiles(t *testing.T) {
	e := newEnv(t)
	if err := os.Mkdir(e.path("dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	targets := map[string]string{"directory": e.path("dir")}
	for name, p := range specialFiles(t, e.dir) {
		targets[name] = p
	}
	for name, p := range targets {
		done := make(chan jobs.Result, 1)
		go func() {
			done <- e.run(Read(), e.session, protocol.FileReadSpec{Path: p, UploadID: protocol.NewID(), MaxBytes: 1 << 20})
		}()
		select {
		case r := <-done:
			if r.Status != protocol.StatusRejected {
				t.Errorf("%s: status = %s (%s)", name, r.Status, r.Message)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("reading a %s blocked", name)
		}
	}
	if len(e.blobs.uploads) != 0 {
		t.Errorf("%d uploads of non-regular files", len(e.blobs.uploads))
	}
}

// ---- file.write ----

func (e *env) writeSpec(name string, data []byte, overwrite bool) protocol.FileWriteSpec {
	id, sum := e.blobs.add(data)
	return protocol.FileWriteSpec{Path: e.path(name), BlobID: id, SHA256: sum, SizeBytes: int64(len(data)), Overwrite: overwrite}
}

func TestWriteNewFile(t *testing.T) {
	e := newEnv(t)
	data := []byte("new content\n")
	r := e.run(Write(), e.session, e.writeSpec("new.txt", data, false))
	wantStatus(t, r, protocol.StatusSucceeded)
	if res := r.Result.(protocol.FileWriteResult); res.SizeBytes != int64(len(data)) {
		t.Errorf("result = %+v", res)
	}
	got, err := os.ReadFile(e.path("new.txt"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("file content = %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(e.path("new.txt")); fi.Mode().Perm() != 0o600 {
			t.Errorf("new file mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	if got := strings.Join(e.names(), ","); got != "new.txt" {
		t.Errorf("temporary files left behind: %s", got)
	}
	// The parent directory must exist; nothing is created on the way.
	r = e.run(Write(), e.session, e.writeSpec(filepath.Join("no", "such", "dir", "f"), data, true))
	wantStatus(t, r, protocol.StatusFailed)
	if _, err := os.Stat(e.path("no")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a missing parent directory was created")
	}
}

func TestWriteNeverOverwritesUnlessAsked(t *testing.T) {
	e := newEnv(t)
	e.write("keep.txt", "original", 0o644)
	r := e.run(Write(), e.session, e.writeSpec("keep.txt", []byte("replacement"), false))
	wantStatus(t, r, protocol.StatusRejected)
	if got, _ := os.ReadFile(e.path("keep.txt")); string(got) != "original" {
		t.Fatalf("file was overwritten: %q", got)
	}
	if e.blobs.downloads != 0 {
		t.Error("the blob was downloaded although the write could not happen")
	}

	// The file appears while the blob is downloading: still not replaced.
	e.blobs.duringDownload = func(string) { e.write("race.txt", "appeared", 0o600) }
	r = e.run(Write(), e.session, e.writeSpec("race.txt", []byte("replacement"), false))
	e.blobs.duringDownload = nil
	wantStatus(t, r, protocol.StatusRejected)
	if got, _ := os.ReadFile(e.path("race.txt")); string(got) != "appeared" {
		t.Fatalf("a file created during the download was replaced: %q", got)
	}

	// With overwrite the content is replaced and owner-visible permissions stay.
	r = e.run(Write(), e.session, e.writeSpec("keep.txt", []byte("replacement"), true))
	wantStatus(t, r, protocol.StatusSucceeded)
	if got, _ := os.ReadFile(e.path("keep.txt")); string(got) != "replacement" {
		t.Fatalf("content = %q", got)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(e.path("keep.txt")); fi.Mode().Perm() != 0o644 {
			t.Errorf("mode after overwrite = %v, want the existing 0644", fi.Mode().Perm())
		}
	}
	if got := strings.Join(e.names(), ","); got != "keep.txt,race.txt" {
		t.Errorf("temporary files left behind: %s", got)
	}
}

func TestWriteHashOrSizeMismatchNeverLands(t *testing.T) {
	for _, leave := range []bool{false, true} {
		e := newEnv(t)
		e.blobs.leaveBad = leave
		e.write("existing.txt", "original", 0o600)
		good := []byte("the signed content")
		id, sum := e.blobs.add([]byte("tampered content!!"))
		goodSum := sha256.Sum256(good)

		for name, spec := range map[string]protocol.FileWriteSpec{
			"hash mismatch, new file":   {Path: e.path("new.bin"), BlobID: id, SHA256: hex.EncodeToString(goodSum[:]), SizeBytes: 18},
			"hash mismatch, overwrite":  {Path: e.path("existing.txt"), BlobID: id, SHA256: hex.EncodeToString(goodSum[:]), SizeBytes: 18, Overwrite: true},
			"size mismatch":             {Path: e.path("new.bin"), BlobID: id, SHA256: sum, SizeBytes: 17},
			"size mismatch, overwrite":  {Path: e.path("existing.txt"), BlobID: id, SHA256: sum, SizeBytes: 19, Overwrite: true},
			"unknown blob":              {Path: e.path("new.bin"), BlobID: protocol.NewID(), SHA256: sum, SizeBytes: 18},
			"unknown blob, overwriting": {Path: e.path("existing.txt"), BlobID: protocol.NewID(), SHA256: sum, SizeBytes: 18, Overwrite: true},
		} {
			r := e.run(Write(), e.session, spec)
			if r.Status == protocol.StatusSucceeded {
				t.Errorf("%s: succeeded", name)
			}
			if strings.Contains(name, "mismatch") && r.Status != protocol.StatusRejected {
				t.Errorf("%s: status = %s, want rejected", name, r.Status)
			}
			if got, _ := os.ReadFile(e.path("existing.txt")); string(got) != "original" {
				t.Fatalf("%s: the existing file was touched: %q", name, got)
			}
			// Neither the destination nor any temporary file is left.
			if got := strings.Join(e.names(), ","); got != "existing.txt" {
				t.Fatalf("%s (leave=%v): directory now contains %s", name, leave, got)
			}
		}
	}
}

func TestWriteRefusesSymlinkAndDirectoryDestinations(t *testing.T) {
	e := newEnv(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.conf")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.path("dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, victim, e.path("link"))
	symlink(t, e.path("nowhere"), e.path("dangling"))
	before := strings.Join(e.names(), ",")

	for _, overwrite := range []bool{false, true} {
		for _, name := range []string{"link", "dangling", "dir"} {
			r := e.run(Write(), e.session, e.writeSpec(name, []byte("payload"), overwrite))
			if r.Status != protocol.StatusRejected {
				t.Errorf("%s overwrite=%v: status = %s (%s)", name, overwrite, r.Status, r.Message)
			}
		}
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatalf("wrote through a symbolic link: %q", got)
	}
	if _, err := os.Lstat(e.path("nowhere")); !errors.Is(err, os.ErrNotExist) {
		t.Error("wrote through a dangling symbolic link")
	}
	if got := strings.Join(e.names(), ","); got != before {
		t.Errorf("directory changed: %s (was %s)", got, before)
	}
	for name, p := range specialFiles(t, e.dir) {
		spec := e.writeSpec("x", []byte("payload"), true)
		spec.Path = p
		if r := e.run(Write(), e.session, spec); r.Status != protocol.StatusRejected {
			t.Errorf("overwriting a %s: %s", name, r.Status)
		}
	}
}

func TestWriteIsAtomic(t *testing.T) {
	// While the blob is still arriving, readers of the destination see the
	// complete old content; the new content appears in one step.
	e := newEnv(t)
	old := strings.Repeat("old", 1000)
	e.write("config.json", old, 0o600)
	fresh := bytes.Repeat([]byte("new"), 50000)
	var seenDuring string
	e.blobs.duringDownload = func(tmp string) {
		data, _ := os.ReadFile(e.path("config.json"))
		seenDuring = string(data)
		if filepath.Dir(tmp) != e.dir {
			t.Errorf("temporary file %s is not next to the destination", tmp)
		}
		if runtime.GOOS != "windows" {
			if fi, err := os.Stat(tmp); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("temporary file mode = %v, %v", fi.Mode().Perm(), err)
			}
		}
	}
	r := e.run(Write(), e.session, e.writeSpec("config.json", fresh, true))
	wantStatus(t, r, protocol.StatusSucceeded)
	if seenDuring != old {
		t.Error("the destination changed before the download was complete and verified")
	}
	if got, _ := os.ReadFile(e.path("config.json")); !bytes.Equal(got, fresh) {
		t.Error("new content is not complete")
	}
	if got := strings.Join(e.names(), ","); got != "config.json" {
		t.Errorf("temporary files left behind: %s", got)
	}
}

func TestWriteNeedsTheSessionUntilTheEnd(t *testing.T) {
	// The session ends while the blob is downloading: nothing is written.
	e := newEnv(t)
	e.write("existing.txt", "original", 0o600)
	e.blobs.duringDownload = func(string) { e.sessions.end(e.session) }
	r := e.run(Write(), e.session, e.writeSpec("existing.txt", []byte("replacement"), true))
	wantStatus(t, r, protocol.StatusRejected)
	if got, _ := os.ReadFile(e.path("existing.txt")); string(got) != "original" {
		t.Fatalf("written after the session ended: %q", got)
	}
	if got := strings.Join(e.names(), ","); got != "existing.txt" {
		t.Errorf("temporary files left behind: %s", got)
	}
}
