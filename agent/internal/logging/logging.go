// Package logging sets up the agent's structured (JSON) logging: a rotating
// agent.log, optional stderr output in the foreground, and redaction so that
// tokens, keys and script bodies never reach a log line.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Redacted is the placeholder written instead of a secret.
const Redacted = "[REDACTED]"

var (
	enrollTokenRe = regexp.MustCompile(`dz_enroll_[A-Za-z0-9._~+/=-]+`)
	privateKeyRe  = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\z)`)
)

// sensitiveKeys are attribute names whose values are never logged.
var sensitiveKeys = map[string]struct{}{
	"token": {}, "enrollment_token": {}, "password": {}, "secret": {},
	"private_key": {}, "key_pem": {}, "authorization": {}, "body": {},
	"script": {}, "script_body": {}, "uninstall_code": {}, "code": {},
	"env": {}, "signature": {}, "signed_payload": {},
}

// Redact removes enrollment tokens and PEM private keys from s.
func Redact(s string) string {
	if strings.Contains(s, "dz_enroll_") {
		s = enrollTokenRe.ReplaceAllString(s, "dz_enroll_"+Redacted)
	}
	if strings.Contains(s, "PRIVATE KEY-----") {
		s = privateKeyRe.ReplaceAllString(s, Redacted)
	}
	return s
}

// replaceAttr is the slog hook applying redaction to every attribute.
func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if _, hit := sensitiveKeys[strings.ToLower(a.Key)]; hit {
		return slog.String(a.Key, Redacted)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		if s := a.Value.String(); s != "" {
			if r := Redact(s); r != s {
				return slog.String(a.Key, r)
			}
		}
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			return slog.String(a.Key, Redact(v.Error()))
		case fmt.Stringer:
			return slog.String(a.Key, Redact(v.String()))
		}
	default:
	}
	return a
}

// redactingHandler additionally redacts the log message itself.
type redactingHandler struct{ slog.Handler }

func (h redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	if m := Redact(r.Message); m != r.Message {
		r.Message = m
	}
	return h.Handler.Handle(ctx, r)
}

func (h redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return redactingHandler{h.Handler.WithAttrs(attrs)}
}

func (h redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{h.Handler.WithGroup(name)}
}

// Options configures New.
type Options struct {
	// File is the log file path ("" disables file logging).
	File string
	// Stderr additionally logs to standard error (foreground mode).
	Stderr bool
	// Level is the minimum level (default Info).
	Level slog.Level
	// MaxBytes is the rotation threshold (default 10 MiB); Backups is the
	// number of rotated files kept (default 3).
	MaxBytes int64
	Backups  int
}

// New builds the JSON logger. The returned closer flushes and closes the file.
func New(opts Options) (*slog.Logger, io.Closer, error) {
	var writers []io.Writer
	var closer io.Closer = nopCloser{}
	if opts.File != "" {
		rw, err := NewRotatingWriter(opts.File, opts.MaxBytes, opts.Backups)
		if err != nil {
			return nil, nil, err
		}
		writers = append(writers, rw)
		closer = rw
	}
	if opts.Stderr || len(writers) == 0 {
		writers = append(writers, os.Stderr)
	}
	return NewWithWriter(io.MultiWriter(writers...), opts.Level), closer, nil
}

// NewWithWriter builds the redacting JSON logger on an arbitrary writer.
func NewWithWriter(w io.Writer, level slog.Level) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: replaceAttr})
	return slog.New(redactingHandler{h})
}

// ForJob returns a logger whose every line carries the correlation ids.
func ForJob(l *slog.Logger, deviceID, jobRunID string) *slog.Logger {
	return l.With(slog.String("device_id", deviceID), slog.String("job_run_id", jobRunID))
}

// Discard returns a logger that drops everything (tests).
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// RotatingWriter is a size-based rotating log file writer. Files are created
// owner-only (0600).
type RotatingWriter struct {
	mu      sync.Mutex
	path    string
	max     int64
	backups int
	f       *os.File
	size    int64
}

// NewRotatingWriter opens (appending to) path.
func NewRotatingWriter(path string, maxBytes int64, backups int) (*RotatingWriter, error) {
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	if backups <= 0 {
		backups = 3
	}
	w := &RotatingWriter{path: path, max: maxBytes, backups: backups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// Write implements io.Writer; it rotates before a write that would exceed the limit.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.size > 0 && w.size+int64(len(p)) > w.max {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingWriter) rotate() error {
	_ = w.f.Close()
	w.f = nil
	_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.backups))
	for i := w.backups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	_ = os.Rename(w.path, w.path+".1")
	return w.open()
}

// Close closes the file.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
