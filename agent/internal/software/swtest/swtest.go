// Package swtest holds the test doubles shared by the tests of the software,
// package, patch and reboot packages: a command recorder for platform.Fake, a
// fake blob client and a JobContext builder. It is only imported by tests.
package swtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

// Call is one recorded command.
type Call struct {
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stdin  string
	AsUser *platform.User
}

// Line is the command as "path arg arg ...".
func (c Call) Line() string { return strings.Join(append([]string{c.Path}, c.Args...), " ") }

// HasEnv reports whether the command carried the KEY=VALUE variable.
func (c Call) HasEnv(kv string) bool {
	for _, e := range c.Env {
		if e == kv {
			return true
		}
	}
	return false
}

// Reply is the scripted outcome of a command.
type Reply struct {
	Stdout string
	Stderr string
	Exit   int
	Err    error
}

// Recorder records every command run through a platform.Fake and answers
// with the scripted replies. Nothing is ever executed.
type Recorder struct {
	mu    sync.Mutex
	calls []Call
	// Respond decides the reply of a command (nil: exit 0, no output).
	Respond func(c Call) Reply
}

// Run is a platform.Fake RunFunc.
func (r *Recorder) Run(ctx context.Context, cmd platform.Command) (int, error) {
	c := Call{Path: cmd.Path, Args: append([]string(nil), cmd.Args...), Env: append([]string(nil), cmd.Env...), Dir: cmd.Dir, AsUser: cmd.AsUser}
	if cmd.Stdin != nil {
		b, _ := io.ReadAll(cmd.Stdin)
		c.Stdin = string(b)
	}
	r.mu.Lock()
	r.calls = append(r.calls, c)
	respond := r.Respond
	r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return platform.ExitCodeUnknown, err
	}
	var rep Reply
	if respond != nil {
		rep = respond(c)
	}
	if rep.Err != nil {
		return platform.ExitCodeUnknown, rep.Err
	}
	if cmd.Stdout != nil && rep.Stdout != "" {
		_, _ = io.WriteString(cmd.Stdout, rep.Stdout)
	}
	if cmd.Stderr != nil && rep.Stderr != "" {
		_, _ = io.WriteString(cmd.Stderr, rep.Stderr)
	}
	return rep.Exit, nil
}

// Calls returns a copy of the recorded commands.
func (r *Recorder) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Call(nil), r.calls...)
}

// Lines returns the recorded commands as command lines.
func (r *Recorder) Lines() []string {
	calls := r.Calls()
	lines := make([]string, len(calls))
	for i, c := range calls {
		lines[i] = c.Line()
	}
	return lines
}

// Platform returns a platform.Fake whose commands go to the recorder. user
// nil means nobody is logged in.
func (r *Recorder) Platform(user *platform.User) *platform.Fake {
	return &platform.Fake{User: user, RunFunc: r.Run}
}

// Lookup is a tool lookup that "finds" exactly the named tools under /fake/bin.
func Lookup(tools ...string) func(string) string {
	set := map[string]bool{}
	for _, t := range tools {
		set[t] = true
	}
	return func(name string) string {
		if set[name] {
			return "/fake/bin/" + name
		}
		return ""
	}
}

// Blobs is a fake jobs.BlobClient serving one blob.
type Blobs struct {
	mu sync.Mutex
	// Content is what the server delivers.
	Content []byte
	// Err, if set, is returned instead of downloading.
	Err error
	// Corrupt delivers the content without verifying it (a broken client), so
	// tests can prove that handlers re-verify what is on disk.
	Corrupt   bool
	Downloads int
}

// SHA256 is the hex SHA-256 of b.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Download implements jobs.BlobClient.
func (b *Blobs) Download(_ context.Context, _ string, dst io.Writer, sizeBytes int64, sha256Hex string) error {
	b.mu.Lock()
	b.Downloads++
	b.mu.Unlock()
	if b.Err != nil {
		return b.Err
	}
	if _, err := dst.Write(b.Content); err != nil {
		return err
	}
	if b.Corrupt {
		return nil
	}
	if int64(len(b.Content)) != sizeBytes {
		return transport.ErrSizeMismatch
	}
	if SHA256(b.Content) != sha256Hex {
		return transport.ErrHashMismatch
	}
	return nil
}

// DownloadFile implements jobs.BlobClient with the semantics of the real
// client: the file is removed again on any failure.
func (b *Blobs) DownloadFile(ctx context.Context, blobID, destPath string, sizeBytes int64, sha256Hex string) error {
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = b.Download(ctx, blobID, f, sizeBytes, sha256Hex)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(destPath)
	}
	return err
}

// Upload implements jobs.BlobClient.
func (b *Blobs) Upload(context.Context, string, io.Reader, int64) error {
	return errors.New("not implemented")
}

// Job is a JobContext with its captured output.
type Job struct {
	*jobs.JobContext
	Out    *bytes.Buffer
	ErrOut *bytes.Buffer
}

// NewJob builds a JobContext for a handler test. spec is marshalled to JSON
// unless it already is a json.RawMessage or a string of JSON.
func NewJob(ctx context.Context, plat platform.Platform, tempDir string, spec any) *Job {
	var raw json.RawMessage
	switch s := spec.(type) {
	case nil:
	case json.RawMessage:
		raw = s
	case string:
		raw = json.RawMessage(s)
	default:
		b, err := json.Marshal(spec)
		if err != nil {
			panic(err)
		}
		raw = b
	}
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	return &Job{
		JobContext: &jobs.JobContext{
			Ctx:            ctx,
			DeviceID:       "00000000-0000-4000-8000-000000000001",
			JobRunID:       "00000000-0000-4000-8000-000000000002",
			Spec:           raw,
			TimeoutSeconds: 300,
			Stdout:         &syncWriter{w: out},
			Stderr:         &syncWriter{w: errOut},
			Log:            logging.Discard(),
			Platform:       plat,
			Sessions:       jobs.NoSessions{},
			TempDir:        tempDir,
		},
		Out:    out,
		ErrOut: errOut,
	}
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
