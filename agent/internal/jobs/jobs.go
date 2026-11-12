// Package jobs runs server-dispatched jobs: a handler registry keyed by job
// kind, bounded concurrency with a bounded queue, cancellation, timeouts,
// output streaming and the job.ack / job.output / job.result messages.
//
// The manager only ever receives dispatches that already passed
// signed-envelope verification; it validates the dispatch fields and each
// handler validates its own spec.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Sender delivers an agent -> server message. Implementations may block
// while the agent is disconnected.
type Sender interface {
	Send(ctx context.Context, msgType string, payload any) error
}

// BlobClient is the blob download / upload helper handed to handlers
// (implemented by transport.BlobClient). Size and hash always come from the
// signed job spec and are verified before a download may be used.
type BlobClient interface {
	Download(ctx context.Context, blobID string, dst io.Writer, sizeBytes int64, sha256Hex string) error
	DownloadFile(ctx context.Context, blobID, destPath string, sizeBytes int64, sha256Hex string) error
	Upload(ctx context.Context, uploadID string, src io.Reader, sizeBytes int64) error
}

// SessionLookup answers whether a remote session is currently active
// (file jobs require an active "files" session).
type SessionLookup interface {
	ActiveSession(sessionID string) (kind string, ok bool)
}

// NoSessions is a SessionLookup without any active session.
type NoSessions struct{}

// ActiveSession implements SessionLookup.
func (NoSessions) ActiveSession(string) (string, bool) { return "", false }

// Result is what a handler returns; the manager turns it into job.result.
type Result struct {
	// Status is one of the protocol job statuses.
	Status string
	// ExitCode is set when a process ran to completion.
	ExitCode *int
	// Message is a short human-readable explanation (never secrets).
	Message string
	// Result is the kind-specific result object (job.result.result), or nil.
	Result any
	// After, if set, runs once the job.result has been handed to the sender
	// (used by agent.uninstall, which must report before removing itself).
	After func()
}

// Succeeded is a successful result without details.
func Succeeded() Result { return Result{Status: protocol.StatusSucceeded} }

// SucceededWith is a successful result with a kind-specific result object.
func SucceededWith(result any) Result {
	return Result{Status: protocol.StatusSucceeded, Result: result}
}

// Failed is a failure with a message.
func Failed(format string, args ...any) Result {
	return Result{Status: protocol.StatusFailed, Message: fmt.Sprintf(format, args...)}
}

// Rejected is a validation failure.
func Rejected(format string, args ...any) Result {
	return Result{Status: protocol.StatusRejected, Message: fmt.Sprintf(format, args...)}
}

// Unsupported is the graceful "the OS cannot do this" result. The message
// always starts with "not supported on this OS: ".
func Unsupported(format string, args ...any) Result {
	return Result{Status: protocol.StatusUnsupported, Message: "not supported on this OS: " + fmt.Sprintf(format, args...)}
}

// FromExitCode maps a process exit code to succeeded (0) or failed.
func FromExitCode(code int) Result {
	r := Result{Status: protocol.StatusSucceeded, ExitCode: &code}
	if code != 0 {
		r.Status = protocol.StatusFailed
		r.Message = fmt.Sprintf("exit code %d", code)
	}
	return r
}

// FromError maps common errors to a result.
func FromError(err error) Result {
	switch {
	case errors.Is(err, platform.ErrNoConsoleUser):
		return Failed("no logged-in user")
	case errors.Is(err, platform.ErrUnsupported):
		return Result{Status: protocol.StatusUnsupported, Message: err.Error()}
	default:
		return Failed("%v", err)
	}
}

// JobContext is everything a handler gets for one job run.
type JobContext struct {
	// Ctx is cancelled on job.cancel, on timeout and on agent shutdown.
	// Handlers must stop promptly; platform.Run kills the process tree.
	Ctx context.Context
	// DeviceID and JobRunID are the correlation ids.
	DeviceID string
	JobRunID string
	Kind     string
	// Spec is the raw JSON "spec" object of the dispatch. Handlers decode it
	// into the typed struct from the protocol package and validate every field.
	Spec json.RawMessage
	// SessionID is the session the job belongs to ("" if none).
	SessionID string
	// TimeoutSeconds is the effective timeout.
	TimeoutSeconds int
	// Stdout and Stderr stream to job.output (chunked, capped, UTF-8 safe).
	Stdout io.Writer
	Stderr io.Writer
	// Log carries job_run_id and device_id on every line.
	Log *slog.Logger
	// Platform is the OS services handle.
	Platform platform.Platform
	// Blobs downloads / uploads over the pinned mTLS channel.
	Blobs BlobClient
	// Sessions tells whether a remote session is active.
	Sessions SessionLookup
	// TempDir is a root-only directory for the job's temporary files.
	TempDir string
}

// DecodeSpec unmarshals the spec into v. Unknown fields are ignored so that
// additive protocol changes do not break older agents.
func (jc *JobContext) DecodeSpec(v any) error {
	if len(jc.Spec) == 0 {
		return nil
	}
	if err := json.Unmarshal(jc.Spec, v); err != nil {
		return fmt.Errorf("invalid spec: %w", err)
	}
	return nil
}

// Handler implements one job kind.
type Handler interface {
	Handle(jc *JobContext) Result
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(jc *JobContext) Result

// Handle implements Handler.
func (f HandlerFunc) Handle(jc *JobContext) Result { return f(jc) }
