// Package software collects the installed-software inventory
// (PROTOCOL.md section 7.2) and holds the helpers shared by the software
// deployment, custom package and patch packages: running a package-manager
// tool with bounded output, locating tools in trusted directories, querying
// one package's state, comparing versions and the "Homebrew never runs as
// root" rule.
//
// Parsers of command output and file content live in untagged files and are
// unit-tested with fixtures for all three operating systems; the per-OS
// gatherers (gather_windows.go, gather_darwin.go, gather_linux.go) are thin.
package software

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Runner is the part of platform.Platform needed to run a tool.
type Runner interface {
	Run(ctx context.Context, cmd platform.Command) (exitCode int, err error)
}

// Output limits of a captured tool run.
const (
	MaxToolStdout = 8 << 20
	MaxToolStderr = 64 << 10
)

// LimitedBuffer keeps at most Limit bytes and silently drops the rest (a
// tool must never be blocked or killed because it talks too much).
type LimitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	Limit     int
	Truncated bool
}

// Write implements io.Writer; it always reports the whole slice as written.
func (b *LimitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.Limit - b.buf.Len()
	switch {
	case room <= 0:
		b.Truncated = b.Truncated || len(p) > 0
	case len(p) > room:
		b.buf.Write(p[:room])
		b.Truncated = true
	default:
		b.buf.Write(p)
	}
	return len(p), nil
}

// String returns what was kept.
func (b *LimitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Tail forwards everything to W (when set) and remembers the last Keep bytes,
// so a handler can stream an installer's output to the job and still inspect
// the end of it.
type Tail struct {
	mu   sync.Mutex
	W    io.Writer
	Keep int
	buf  []byte
}

// NewTail returns a Tail that forwards to w and keeps the last keep bytes.
func NewTail(w io.Writer, keep int) *Tail { return &Tail{W: w, Keep: keep} }

// Write implements io.Writer.
func (t *Tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf = append(t.buf, p...)
	if extra := len(t.buf) - t.Keep; extra > 0 {
		t.buf = append(t.buf[:0], t.buf[extra:]...)
	}
	w := t.W
	t.mu.Unlock()
	if w != nil {
		// The job output writer never fails in a way the tool could act on.
		_, _ = w.Write(p)
	}
	return len(p), nil
}

// String returns the remembered tail.
func (t *Tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// ToolResult is the captured outcome of a tool run.
type ToolResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Output runs cmd through r with a timeout and captures bounded stdout and
// stderr. The locale is forced to C so that parsers see untranslated output.
// err is non-nil only when the tool could not be run or the context ended; a
// non-zero exit code is reported in the result.
func Output(ctx context.Context, r Runner, timeout time.Duration, cmd platform.Command) (ToolResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	stdout := &LimitedBuffer{Limit: MaxToolStdout}
	stderr := &LimitedBuffer{Limit: MaxToolStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = WithCLocale(cmd.Env)
	code, err := r.Run(ctx, cmd)
	return ToolResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}, err
}

// WithCLocale adds LC_ALL=C and LANG=C unless the caller already set them.
func WithCLocale(env []string) []string {
	hasAll, hasLang := false, false
	for _, kv := range env {
		hasAll = hasAll || strings.HasPrefix(kv, "LC_ALL=")
		hasLang = hasLang || strings.HasPrefix(kv, "LANG=")
	}
	out := append([]string(nil), env...)
	if !hasAll {
		out = append(out, "LC_ALL=C")
	}
	if !hasLang {
		out = append(out, "LANG=C")
	}
	return out
}

// bom is the Unicode byte order mark.
const bom = rune(0xFEFF)

// Clean makes a string from a tool or a file safe to report: valid UTF-8, no
// control characters, trimmed and at most max bytes (cut at a rune boundary).
func Clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || r == bom {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}

// Lines splits tool output into lines without the line terminators. A lone
// carriage return (progress spinners redraw the same line) keeps only what
// follows it.
func Lines(out string) []string {
	out = strings.TrimPrefix(out, string(bom))
	raw := strings.Split(out, "\n")
	lines := make([]string, 0, len(raw))
	for _, l := range raw {
		l = strings.TrimSuffix(l, "\r")
		if i := strings.LastIndexByte(l, '\r'); i >= 0 {
			l = l[i+1:]
		}
		lines = append(lines, l)
	}
	return lines
}
