// Package agentcore is the agent's main loop: enrollment, the control
// connection, heartbeats, periodic reporters and the routing of incoming
// messages. Every signed command type goes through the protocol.Verifier
// before anything else looks at its payload.
package agentcore

import (
	"context"
	"log/slog"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// SessionHandler implements remote sessions (terminal / files / desktop).
// Every method is called only for commands that passed signed-envelope
// verification and field validation. Methods are called from the connection's
// read loop and must return quickly (do long work in goroutines).
//
// The handler owns the transparency rules of PROTOCOL.md section 6.5
// (consent prompt, visible indicator, fail closed on connection loss). When a
// terminal session becomes active it must call Env.Seq.Open(sessionID), and
// Env.Seq.Close(sessionID) when it ends, so session.input replay protection works.
type SessionHandler interface {
	// Kinds lists the supported session kinds (reported in hello.capabilities
	// as "session.<kind>").
	Kinds() []string
	// Start handles session.start.
	Start(ctx context.Context, start protocol.SessionStart)
	// Input handles session.input (seq already checked: exactly last+1).
	Input(ctx context.Context, in protocol.SessionInput)
	// End handles session.end.
	End(ctx context.Context, end protocol.SessionEnd)
	// ConnectionLost is called when the control connection drops; every
	// session must end (fail closed).
	ConnectionLost()
	// ActiveSession reports whether a session is active and its kind.
	ActiveSession(sessionID string) (kind string, ok bool)
}

// UpdateHandler implements agent self-update for a verified and validated
// update.available command. It must return quickly.
type UpdateHandler interface {
	Available(ctx context.Context, update protocol.UpdateAvailable)
}

// ReporterFunc collects one periodic report: the message type to send and its payload.
type ReporterFunc func(ctx context.Context) (msgType string, payload any, err error)

// Env is what the agent core hands to pluggable components (session handler,
// update handler, extra job handlers and reporters built by later packages).
type Env struct {
	Paths    config.Paths
	Log      *slog.Logger
	Platform platform.Platform
	Version  string
	// Sender delivers agent -> server messages; it blocks while disconnected.
	Sender jobs.Sender
	// Blobs downloads / uploads over the pinned mTLS channel.
	Blobs jobs.BlobClient
	// Seq is the session.input sequence tracker used by the Verifier.
	Seq *protocol.SeqTracker
	// DeviceID returns the device id ("" before enrollment).
	DeviceID func() string
}

// noSessions is the default SessionHandler of a build without remote
// sessions: every session.start is answered with session.status "failed".
type noSessions struct{ send jobs.Sender }

func (noSessions) Kinds() []string { return nil }

func (n noSessions) Start(ctx context.Context, start protocol.SessionStart) {
	_ = n.send.Send(ctx, protocol.TypeSessionStatus, protocol.SessionStatus{
		SessionID: start.SessionID,
		State:     protocol.SessionFailed,
		Reason:    "not supported in this build",
	})
}

func (noSessions) Input(context.Context, protocol.SessionInput) {}
func (noSessions) End(context.Context, protocol.SessionEnd)     {}
func (noSessions) ConnectionLost()                              {}

func (noSessions) ActiveSession(string) (string, bool) { return "", false }

// noUpdates is the default UpdateHandler of a build without self-update.
type noUpdates struct{ send jobs.Sender }

func (n noUpdates) Available(ctx context.Context, u protocol.UpdateAvailable) {
	_ = n.send.Send(ctx, protocol.TypeUpdateStatus, protocol.UpdateStatus{
		Version: u.Version,
		State:   protocol.UpdateFailed,
		Error:   "self-update is not supported in this build",
	})
}

type reporter struct {
	name     string
	interval func() time.Duration
	collect  ReporterFunc
	run      chan struct{} // serialises collections of this reporter
	lastRun  time.Time     // guarded by Agent.repMu
}
