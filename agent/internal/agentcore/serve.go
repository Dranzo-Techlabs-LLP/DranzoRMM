package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
	"unicode"

	"github.com/coder/websocket"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/inventory"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/transport"
	"github.com/dranzo/dranzormm/agent/internal/trust"
)

func (b blobAdapter) Download(ctx context.Context, blobID string, dst io.Writer, sizeBytes int64, sha256Hex string) error {
	return b.client().Download(ctx, blobID, dst, sizeBytes, sha256Hex)
}

func (b blobAdapter) DownloadFile(ctx context.Context, blobID, destPath string, sizeBytes int64, sha256Hex string) error {
	return b.client().DownloadFile(ctx, blobID, destPath, sizeBytes, sha256Hex)
}

func (b blobAdapter) Upload(ctx context.Context, uploadID string, src io.Reader, sizeBytes int64) error {
	return b.client().Upload(ctx, uploadID, src, sizeBytes)
}

// capabilities lists the job kinds and session kinds of this build.
func (a *Agent) capabilities() []string {
	caps := a.jobs.Kinds()
	for _, k := range a.sessionHandler().Kinds() {
		caps = append(caps, "session."+k)
	}
	return caps
}

// serve runs one established connection: hello, then the read loop. The
// heartbeat and reporter loops start once hello.ack arrived.
func (a *Agent) serve(ctx context.Context, conn *transport.Conn) error {
	hello := protocol.Hello{
		AgentVersion:    a.opts.Version,
		ProtocolVersion: protocol.Version,
		OS:              platform.OSFamily,
		Arch:            inventory.Arch(),
		Hostname:        inventory.Hostname(),
		Capabilities:    a.capabilities(),
		TrustKeyIDs:     a.trust.KeyIDs(),
	}
	// hello must be the first message on the wire: queue it before the
	// connection becomes visible to job output and reporters.
	if err := sendOn(ctx, conn, protocol.TypeHello, hello); err != nil {
		return err
	}
	a.setConn(conn)
	defer func() {
		a.setConn(nil)
		// Sessions never outlive the control connection (fail closed).
		a.sessionHandler().ConnectionLost()
		a.seq.CloseAll()
	}()

	acked := make(chan struct{})
	ackedOnce := false
	loopCtx, stopLoops := context.WithCancel(ctx)
	defer stopLoops()
	go func() {
		timeout := a.opts.HelloAckTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-loopCtx.Done():
			return
		case <-t.C:
			a.log.Warn("no hello.ack from server; reconnecting")
			conn.Close(websocket.StatusPolicyViolation, "hello.ack timeout")
			return
		case <-acked:
		}
		go a.reporterLoop(loopCtx)
		a.heartbeatLoop(loopCtx, conn)
	}()

	for {
		data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		env, err := protocol.ParseEnvelope(data)
		if err != nil {
			a.replyError(ctx, conn, protocol.ErrCodeMalformed, "invalid envelope", "")
			continue
		}
		if env.Version > protocol.Version {
			a.replyError(ctx, conn, protocol.ErrCodeUnsupportedVersion, fmt.Sprintf("protocol version %d is not supported", env.Version), env.ID)
			conn.CloseAfterFlush(websocket.StatusProtocolError, "unsupported protocol version", 2*time.Second)
			return errors.New("server uses an unsupported protocol version")
		}
		if env.Version != protocol.Version {
			a.replyError(ctx, conn, protocol.ErrCodeMalformed, "invalid protocol version", env.ID)
			continue
		}

		switch {
		case protocol.IsSignedType(env.Type):
			// SECURITY: nothing below this call sees the payload unless every
			// verification step of PROTOCOL.md section 4.1 passed.
			a.handleSigned(ctx, conn, env)
		case env.Type == protocol.TypeHelloAck:
			a.handleHelloAck(env)
			if !ackedOnce {
				ackedOnce = true
				close(acked)
			}
		case env.Type == protocol.TypeHeartbeatAck:
			a.lastAck.Store(time.Now().UnixNano())
		case env.Type == protocol.TypeError:
			var p protocol.ErrorPayload
			_ = json.Unmarshal(env.Payload, &p)
			a.log.Warn("server reported an error",
				slog.String("code", printable(p.Code, 64)),
				slog.String("message", printable(p.Message, 512)),
				slog.String("ref_id", printable(p.RefID, 64)))
		default:
			a.replyError(ctx, conn, protocol.ErrCodeUnknownType, "unknown message type", env.ID)
		}
	}
}

// printable makes untrusted text safe for a log line.
func printable(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsPrint(r) {
			out = append(out, r)
		} else {
			out = append(out, '?')
		}
	}
	return logging.Redact(string(out))
}

func (a *Agent) replyError(ctx context.Context, conn *transport.Conn, code, message, refID string) {
	if !protocol.ValidUUID(refID) {
		// Only echo well-formed ids back.
		refID = ""
	}
	if err := sendOn(ctx, conn, protocol.TypeError, protocol.ErrorPayload{Code: code, Message: message, RefID: refID}); err != nil {
		a.log.Debug("could not send error reply", slog.Any("error", err))
	}
}

func (a *Agent) handleHelloAck(env *protocol.Envelope) {
	a.lastAck.Store(time.Now().UnixNano())
	var ack protocol.HelloAck
	if err := json.Unmarshal(env.Payload, &ack); err != nil {
		a.log.Warn("hello.ack payload is invalid; keeping current intervals")
	} else {
		// hello.ack is unsigned: it may only tune intervals, and those are clamped.
		a.cfgMu.Lock()
		changed := a.cfg.ApplyHelloAck(ack)
		cfg := a.cfg
		a.cfgMu.Unlock()
		if changed {
			if err := config.Save(a.paths, &cfg); err != nil {
				a.log.Warn("could not save config", slog.Any("error", err))
			}
		}
		if !ack.ServerTime.IsZero() {
			if skew := time.Since(ack.ServerTime); skew > protocol.ClockSkew || skew < -protocol.ClockSkew {
				a.log.Warn("clock differs from the server by more than 5 minutes; signed commands may be refused",
					slog.Duration("skew", skew))
			}
		}
		a.log.Info("hello acknowledged", slog.Int("heartbeat_seconds", cfg.HeartbeatSeconds))
	}
	a.plugMu.Lock()
	hooks := append([]func(){}, a.helloHooks...)
	a.plugMu.Unlock()
	for _, fn := range hooks {
		fn()
	}
}

// handleSigned verifies a signed command and routes it. On refusal it sends
// the documented error (and, for job.dispatch, the negative job.ack).
func (a *Agent) handleSigned(ctx context.Context, conn *transport.Conn, env *protocol.Envelope) {
	cmd, err := a.verifier.Verify(env)
	if err != nil {
		var ve *protocol.VerifyError
		if !errors.As(err, &ve) {
			ve = &protocol.VerifyError{Code: protocol.ErrCodeMalformed, Message: "verification failed"}
		}
		a.log.Warn("signed command refused",
			slog.String("type", env.Type),
			slog.String("code", ve.Code),
			slog.String("reason", ve.Message),
			slog.String("envelope_id", printable(env.ID, 64)))
		a.replyError(ctx, conn, ve.Code, ve.Message, env.ID)
		if env.Type == protocol.TypeJobDispatch && ve.SignatureVerified {
			var p struct {
				JobRunID string `json:"jobRunId"`
			}
			if json.Unmarshal(ve.Payload, &p) == nil && protocol.ValidUUID(p.JobRunID) {
				_ = sendOn(ctx, conn, protocol.TypeJobAck, protocol.JobAck{JobRunID: p.JobRunID, Accepted: false, Reason: ve.Code})
			}
		}
		return
	}

	malformed := func(what string) {
		a.log.Warn("verified command has an invalid payload", slog.String("type", cmd.Type), slog.String("reason", what))
		a.replyError(ctx, conn, protocol.ErrCodeMalformed, what, env.ID)
	}

	switch cmd.Type {
	case protocol.TypeJobDispatch:
		var d protocol.JobDispatch
		if err := cmd.Decode(&d); err != nil {
			malformed("invalid job.dispatch payload")
			return
		}
		if err := a.jobs.Dispatch(ctx, d); errors.Is(err, jobs.ErrInvalidJobRunID) {
			malformed("jobRunId is not a valid id")
		}

	case protocol.TypeJobCancel:
		var c protocol.JobCancel
		if err := cmd.Decode(&c); err != nil || !protocol.ValidUUID(c.JobRunID) {
			malformed("invalid job.cancel payload")
			return
		}
		if !a.jobs.Cancel(c.JobRunID) {
			a.log.Info("job.cancel for a job that is not running", slog.String("job_run_id", c.JobRunID))
		}

	case protocol.TypeUpdateAvailable:
		var u protocol.UpdateAvailable
		if err := cmd.Decode(&u); err != nil || !protocol.ValidPackageID(u.Version) || len(u.Version) > 64 ||
			!protocol.ValidUUID(u.BlobID) || !protocol.ValidSHA256Hex(u.SHA256) || u.SizeBytes <= 0 || len(u.Ring) > 64 {
			malformed("invalid update.available payload")
			return
		}
		a.log.Info("update.available received", slog.String("version", u.Version), slog.String("ring", printable(u.Ring, 64)))
		a.updateHandler().Available(ctx, u)

	case protocol.TypeSessionStart:
		var s protocol.SessionStart
		if err := cmd.Decode(&s); err != nil || !protocol.ValidUUID(s.SessionID) {
			malformed("invalid session.start payload")
			return
		}
		if reason := validateSessionStart(&s); reason != "" {
			_ = sendOn(ctx, conn, protocol.TypeSessionStatus, protocol.SessionStatus{SessionID: s.SessionID, State: protocol.SessionFailed, Reason: reason})
			return
		}
		a.log.Info("session.start received",
			slog.String("session_id", s.SessionID), slog.String("kind", s.Kind),
			slog.String("consent", s.Consent), slog.String("requested_by", printable(s.RequestedBy, 256)))
		a.sessionHandler().Start(ctx, s)

	case protocol.TypeSessionInput:
		var in protocol.SessionInput
		if err := cmd.Decode(&in); err != nil ||
			(in.Kind != protocol.SessionInputData && in.Kind != protocol.SessionInputResize) {
			malformed("invalid session.input payload")
			return
		}
		a.sessionHandler().Input(ctx, in)

	case protocol.TypeSessionEnd:
		var e protocol.SessionEnd
		if err := cmd.Decode(&e); err != nil || !protocol.ValidUUID(e.SessionID) {
			malformed("invalid session.end payload")
			return
		}
		e.Reason = printable(e.Reason, 256)
		a.sessionHandler().End(ctx, e)

	case protocol.TypeTrustRotate:
		a.handleTrustRotate(ctx, conn, cmd, env.ID)
	}
}

// validateSessionStart checks every field; it returns "" when valid.
func validateSessionStart(s *protocol.SessionStart) string {
	switch s.Kind {
	case protocol.SessionKindTerminal, protocol.SessionKindFiles, protocol.SessionKindDesktop:
	default:
		return "invalid session kind"
	}
	switch s.Consent {
	case protocol.ConsentNone, protocol.ConsentNotify, protocol.ConsentRequire:
	default:
		return "invalid consent mode"
	}
	if s.ConsentTimeoutSeconds < 0 || s.ConsentTimeoutSeconds > 600 {
		return "invalid consentTimeoutSeconds"
	}
	if s.RequestedBy == "" || len(s.RequestedBy) > 256 {
		return "invalid requestedBy"
	}
	// requestedBy is shown to the user: keep it to printable characters.
	s.RequestedBy = printableKeep(s.RequestedBy)
	if s.Kind == protocol.SessionKindTerminal {
		if s.Terminal == nil {
			return "terminal options missing"
		}
		if s.Terminal.Cols < 1 || s.Terminal.Cols > 1000 || s.Terminal.Rows < 1 || s.Terminal.Rows > 1000 {
			return "invalid terminal size"
		}
		switch s.Terminal.RunAs {
		case protocol.RunAsSystem, protocol.RunAsUser:
		default:
			return "invalid terminal runAs"
		}
	}
	return ""
}

func printableKeep(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsPrint(r) {
			out = append(out, r)
		}
	}
	return string(out)
}

// handleTrustRotate applies a VERIFIED trust.rotate. The command was signed
// by a key of the current trust.json (the Verifier checked that); the new
// content is validated completely before anything is replaced.
func (a *Agent) handleTrustRotate(ctx context.Context, conn *transport.Conn, cmd *protocol.Verified, envID string) {
	var r protocol.TrustRotate
	if err := cmd.Decode(&r); err != nil {
		a.replyError(ctx, conn, protocol.ErrCodeMalformed, "invalid trust.rotate payload", envID)
		return
	}
	if _, err := trust.ParseCommandKeys(r.CommandKeys); err != nil {
		a.log.Warn("trust.rotate refused", slog.Any("error", err))
		a.replyError(ctx, conn, protocol.ErrCodeMalformed, "invalid commandKeys: "+err.Error(), envID)
		return
	}
	if r.CACertificates != "" {
		if _, _, err := trust.ParseCABundle([]byte(r.CACertificates)); err != nil {
			a.log.Warn("trust.rotate refused", slog.Any("error", err))
			a.replyError(ctx, conn, protocol.ErrCodeMalformed, "invalid caCertificates: "+err.Error(), envID)
			return
		}
	}
	before := a.trust.KeyIDs()
	if err := a.trust.Replace(r.CommandKeys, []byte(r.CACertificates)); err != nil {
		a.log.Error("trust.rotate could not be applied", slog.Any("error", err))
		a.replyError(ctx, conn, protocol.ErrCodeMalformed, "trust store could not be replaced", envID)
		return
	}
	a.log.Warn("trust store rotated",
		slog.String("signed_by", cmd.KeyID),
		slog.Any("previous_key_ids", before),
		slog.Any("key_ids", a.trust.KeyIDs()),
		slog.Bool("ca_replaced", r.CACertificates != ""))
	// Reconnect: the new hello announces the new trustKeyIds and the new CA
	// pins are exercised immediately.
	a.closeAndReconnect("trust rotated")
}

// ---- heartbeat ----

func (a *Agent) pendingReboot(ctx context.Context) bool {
	a.rebootMu.Lock()
	defer a.rebootMu.Unlock()
	if !a.rebootChecked.IsZero() && time.Since(a.rebootChecked) < 10*time.Minute {
		return a.rebootCached
	}
	if v, err := a.plat.PendingReboot(ctx); err == nil {
		a.rebootCached = v
	}
	a.rebootChecked = time.Now()
	return a.rebootCached
}

func (a *Agent) heartbeat(ctx context.Context) protocol.Heartbeat {
	stats := a.collector.SystemStats(ctx)
	_, rss := a.collector.SelfStats(ctx)
	hb := protocol.Heartbeat{
		Seq:            a.hbSeq.Add(1),
		UptimeSeconds:  stats.UptimeSeconds,
		CPUPercent:     stats.CPUPercent,
		MemUsedPercent: stats.MemUsedPercent,
		PendingReboot:  a.pendingReboot(ctx),
		AgentRSSBytes:  rss,
	}
	if u, err := a.plat.ConsoleUser(ctx); err == nil {
		hb.ConsoleUser = u.Name
	}
	return hb
}

func (a *Agent) heartbeatLoop(ctx context.Context, conn *transport.Conn) {
	for {
		interval := time.Duration(a.Config().HeartbeatSeconds) * time.Second
		// No ack for three intervals: the connection is dead even if TCP has not noticed.
		if last := a.lastAck.Load(); last != 0 && time.Since(time.Unix(0, last)) > 3*interval+10*time.Second {
			a.log.Warn("no heartbeat.ack for three intervals; reconnecting")
			conn.Close(websocket.StatusPolicyViolation, "heartbeat timeout")
			return
		}
		if err := sendOn(ctx, conn, protocol.TypeHeartbeat, a.heartbeat(ctx)); err != nil {
			return
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
