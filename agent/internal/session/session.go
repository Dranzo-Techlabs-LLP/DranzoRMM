// Package session implements remote sessions on the agent side
// (docs/PROTOCOL.md sections 6.5 and 6.6): terminal, files and desktop.
//
// It owns the transparency rules, which are not optional and do not depend
// on the consent mode:
//
//   - consent "require": the logged-in user is asked first; no answer within
//     the timeout means Deny;
//   - consent "notify": the user gets a notification;
//   - in every mode, including "none", a visible indicator naming who is
//     connected is on screen for as long as the session is active, with an
//     "End session" control that ends the session locally;
//   - sessions fail closed: they end when the control connection drops, and
//     a session whose indicator can no longer be shown to a logged-in user
//     ends too.
//
// A terminal session is a new shell on a new pseudo-terminal for the
// technician. Nothing here reads the user's screen, keyboard, camera,
// microphone or the user's own terminals.
package session

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// Limits.
const (
	// MaxSessions is the number of sessions (pending or active) at a time.
	MaxSessions = 4
	// MaxDuration is the longest a session may last.
	MaxDuration = 12 * time.Hour
	// DefaultFlushInterval is how long terminal output is coalesced.
	DefaultFlushInterval = 20 * time.Millisecond

	defaultConsentTimeout = 60 * time.Second
	maxConsentTimeout     = 600 * time.Second
	maxRequestedByBytes   = 256
	maxRequestedByShown   = 120
	maxTerminalSide       = 1000
)

// Reasons reported in session.status.
const (
	ReasonUserDenied           = "user_denied"
	ReasonTimeout              = "timeout"
	ReasonNoUser               = "no_user_logged_in"
	ReasonConsentUnavailable   = "consent_unavailable"
	ReasonConsentPromptFailed  = "consent_prompt_failed"
	ReasonIndicatorUnavailable = "indicator_unavailable"
	ReasonTooManySessions      = "too_many_sessions"
	ReasonEndedByServer        = "ended_by_server"
	ReasonEndedLocally         = "ended_locally"
	ReasonTerminalExited       = "terminal_exited"
	ReasonMaxDuration          = "max_duration"
	ReasonConnectionLost       = "connection_lost"
	ReasonSessionIDReused      = "session_id_reused"
)

// Options tune a Handler; zero values select the production defaults.
type Options struct {
	MaxSessions   int
	MaxDuration   time.Duration
	FlushInterval time.Duration
	// IndicatorRetry is how often a session that started with nobody logged
	// in looks for a user to show the indicator to.
	IndicatorRetry time.Duration
	// StartTerminal replaces the OS pseudo-terminal (tests).
	StartTerminal StartTerminalFunc
}

// Handler is the agentcore.SessionHandler.
type Handler struct {
	send jobs.Sender
	seq  *protocol.SeqTracker
	plat platform.Platform
	log  *slog.Logger
	ui   userui.UI
	opts Options

	mu       sync.Mutex
	sessions map[string]*session
}

var _ agentcore.SessionHandler = (*Handler)(nil)

// New returns a session handler that talks to the user through ui.
func New(env agentcore.Env, ui userui.UI, opts Options) *Handler {
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = MaxSessions
	}
	if opts.MaxDuration <= 0 || opts.MaxDuration > MaxDuration {
		opts.MaxDuration = MaxDuration
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = DefaultFlushInterval
	}
	if opts.IndicatorRetry <= 0 {
		opts.IndicatorRetry = 15 * time.Second
	}
	if opts.StartTerminal == nil {
		opts.StartTerminal = startTerminal
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{
		send:     env.Sender,
		seq:      env.Seq,
		plat:     env.Platform,
		log:      log,
		ui:       ui,
		opts:     opts,
		sessions: map[string]*session{},
	}
}

// Session states inside the agent.
const (
	statePending = iota
	stateActive
	stateEnded
)

type session struct {
	id          string
	kind        string
	requestedBy string
	start       protocol.SessionStart
	log         *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	// done is closed when the session is completely torn down.
	done chan struct{}

	mu        sync.Mutex
	state     int
	endReason string
	term      Terminal
	inputs    chan []byte
}

// end asks the session to end. The first reason wins.
func (s *session) end(reason string) {
	s.mu.Lock()
	if s.endReason == "" {
		s.endReason = reason
	}
	s.mu.Unlock()
	s.cancel()
}

// reason returns why the session ended; a context that ended without an
// explicit reason is the control connection going away.
func (s *session) reason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endReason == "" {
		s.endReason = ReasonConnectionLost
	}
	return s.endReason
}

// Kinds implements agentcore.SessionHandler.
func (h *Handler) Kinds() []string {
	return []string{protocol.SessionKindTerminal, protocol.SessionKindFiles, protocol.SessionKindDesktop}
}

// ActiveSession implements agentcore.SessionHandler: only a session that got
// past consent and whose indicator is up counts as active.
func (h *Handler) ActiveSession(sessionID string) (kind string, ok bool) {
	h.mu.Lock()
	s := h.sessions[sessionID]
	h.mu.Unlock()
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateActive {
		return "", false
	}
	return s.kind, true
}

// CleanRequestedBy makes the technician's display name safe to show: control
// and invisible formatting characters are removed and the length is capped.
func CleanRequestedBy(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || unicode.Is(unicode.Zs, r):
			b.WriteRune(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > maxRequestedByShown {
		out = out[:maxRequestedByShown]
		for len(out) > 0 && !utf8.ValidString(out) {
			out = out[:len(out)-1]
		}
		out = strings.TrimSpace(out)
	}
	return out
}

// Validate checks every field of a session.start and normalises it. It
// returns "" when the command is acceptable.
func Validate(s *protocol.SessionStart) string {
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
	if s.ConsentTimeoutSeconds < 0 || time.Duration(s.ConsentTimeoutSeconds)*time.Second > maxConsentTimeout {
		return "invalid consentTimeoutSeconds"
	}
	if len(s.RequestedBy) > maxRequestedByBytes {
		return "invalid requestedBy"
	}
	s.RequestedBy = CleanRequestedBy(s.RequestedBy)
	if s.RequestedBy == "" {
		// The indicator must be able to say who is connected.
		return "invalid requestedBy"
	}
	if s.Kind == protocol.SessionKindTerminal {
		if s.Terminal == nil {
			return "terminal options missing"
		}
		if s.Terminal.Cols < 1 || s.Terminal.Cols > maxTerminalSide || s.Terminal.Rows < 1 || s.Terminal.Rows > maxTerminalSide {
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

// Start implements agentcore.SessionHandler.
func (h *Handler) Start(ctx context.Context, start protocol.SessionStart) {
	if !protocol.ValidUUID(start.SessionID) {
		h.log.Warn("session.start with an invalid session id ignored")
		return
	}
	log := h.log.With(slog.String("session_id", start.SessionID))
	if reason := Validate(&start); reason != "" {
		log.Warn("session.start rejected", slog.String("reason", reason))
		h.status(ctx, start.SessionID, protocol.SessionFailed, reason)
		return
	}
	log = log.With(slog.String("kind", start.Kind), slog.String("requested_by", start.RequestedBy))

	h.mu.Lock()
	if _, dup := h.sessions[start.SessionID]; dup {
		h.mu.Unlock()
		log.Info("duplicate session.start ignored")
		return
	}
	if len(h.sessions) >= h.opts.MaxSessions {
		h.mu.Unlock()
		log.Warn("session.start refused: too many sessions")
		h.status(ctx, start.SessionID, protocol.SessionFailed, ReasonTooManySessions)
		return
	}
	// The session lives inside the connection's context: when the control
	// connection goes away the context ends and so does the session.
	sctx, cancel := context.WithCancel(ctx)
	s := &session{
		id:          start.SessionID,
		kind:        start.Kind,
		requestedBy: start.RequestedBy,
		start:       start,
		log:         log,
		ctx:         sctx,
		cancel:      cancel,
		done:        make(chan struct{}),
		state:       statePending,
	}
	h.sessions[s.id] = s
	h.mu.Unlock()

	log.Info("remote session requested", slog.String("consent", start.Consent))
	// The session outlives this call by design. It is bound to the
	// connection's context (sctx); only its final status and the last
	// terminal output are sent on a fresh, time-limited context.
	go h.run(s) //nolint:gosec // G118: see above
}

// Input implements agentcore.SessionHandler. The verifier has already
// checked the signature and that seq is exactly last+1.
func (h *Handler) Input(_ context.Context, in protocol.SessionInput) {
	h.mu.Lock()
	s := h.sessions[in.SessionID]
	h.mu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	term, inputs, active := s.term, s.inputs, s.state == stateActive
	s.mu.Unlock()
	if !active || s.kind != protocol.SessionKindTerminal || term == nil {
		s.log.Warn("session.input for a session that is not an active terminal ignored")
		return
	}
	switch in.Kind {
	case protocol.SessionInputData:
		if base64.StdEncoding.DecodedLen(len(in.Data)) > MaxInputBytes+3 {
			s.log.Warn("session.input dropped: too large")
			return
		}
		data, err := base64.StdEncoding.DecodeString(in.Data)
		if err != nil || len(data) > MaxInputBytes {
			s.log.Warn("session.input dropped: invalid data")
			return
		}
		if len(data) == 0 {
			return
		}
		select {
		case inputs <- data:
		default:
			// The shell is not reading and the queue is full. Losing input
			// silently would corrupt what the technician typed: end instead.
			s.log.Warn("terminal input queue is full; ending the session")
			s.end("input_overflow")
		}
	case protocol.SessionInputResize:
		if in.Cols < 1 || in.Cols > maxTerminalSide || in.Rows < 1 || in.Rows > maxTerminalSide {
			s.log.Warn("session.input resize dropped: invalid size")
			return
		}
		if err := term.Resize(in.Cols, in.Rows); err != nil {
			s.log.Debug("terminal resize failed", slog.Any("error", err))
		}
	}
}

// End implements agentcore.SessionHandler.
func (h *Handler) End(_ context.Context, end protocol.SessionEnd) {
	h.mu.Lock()
	s := h.sessions[end.SessionID]
	h.mu.Unlock()
	if s == nil {
		return
	}
	s.log.Info("session.end received", slog.String("server_reason", end.Reason))
	s.end(ReasonEndedByServer)
}

// ConnectionLost implements agentcore.SessionHandler: every session ends
// (fail closed). It returns once the sessions are torn down - shells killed,
// indicators removed - or after a bounded wait.
func (h *Handler) ConnectionLost() {
	h.mu.Lock()
	list := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		list = append(list, s)
	}
	h.mu.Unlock()
	for _, s := range list {
		s.end(ReasonConnectionLost)
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for _, s := range list {
		select {
		case <-s.done:
		case <-deadline.C:
			h.log.Error("sessions did not end in time after the connection was lost")
			return
		}
	}
}

// status sends a session.status message with a bounded wait.
func (h *Handler) status(ctx context.Context, sessionID, state, reason string) {
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := h.send.Send(sctx, protocol.TypeSessionStatus, protocol.SessionStatus{SessionID: sessionID, State: state, Reason: reason}); err != nil {
		h.log.Debug("could not send session.status", slog.String("session_id", sessionID), slog.String("state", state), slog.Any("error", err))
	}
}

// finalStatus reports the end of a session. The session's own context is
// over by then; nothing is sent when the connection is gone (the server ends
// the session on its side when the device disconnects).
func (h *Handler) finalStatus(s *session, state, reason string) {
	if reason == ReasonConnectionLost {
		return
	}
	h.status(context.Background(), s.id, state, reason)
}

func (h *Handler) remove(s *session) {
	h.mu.Lock()
	if h.sessions[s.id] == s {
		delete(h.sessions, s.id)
	}
	h.mu.Unlock()
}

// userPresent reports whether somebody is logged in at the console. An
// error is treated as "present" by the callers (fail closed).
func (h *Handler) userPresent(ctx context.Context) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := h.plat.ConsoleUser(cctx)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, platform.ErrNoConsoleUser):
		return false, nil
	default:
		return true, err
	}
}

func kindLabel(kind string) string {
	switch kind {
	case protocol.SessionKindTerminal:
		return "command line (terminal)"
	case protocol.SessionKindFiles:
		return "file transfer"
	case protocol.SessionKindDesktop:
		return "remote desktop (screen view and control)"
	}
	return kind
}

// Texts shown to the user.
func consentQuestion(s *session, timeout time.Duration) userui.Question {
	return userui.Question{
		Title: "Remote support request",
		Message: fmt.Sprintf("%s is asking to start a remote support session on this computer.\n\nType of access: %s.\n\nAllow this session?",
			s.requestedBy, kindLabel(s.kind)),
		YesLabel:   "Allow",
		NoLabel:    "Deny",
		Timeout:    timeout,
		DefaultYes: false,
	}
}

func indicatorText(s *session) (title, message string) {
	return "Remote session active", fmt.Sprintf("Remote session active: %s\nType of access: %s.", s.requestedBy, kindLabel(s.kind))
}

// run is the life of one session.
func (h *Handler) run(s *session) {
	defer close(s.done)
	defer h.remove(s)
	defer s.cancel()

	fail := func(state, reason string) {
		s.mu.Lock()
		s.state = stateEnded
		s.mu.Unlock()
		s.log.Warn("remote session not started", slog.String("state", state), slog.String("reason", reason))
		h.finalStatus(s, state, reason)
	}
	endedEarly := func() bool {
		if s.ctx.Err() == nil {
			return false
		}
		reason := s.reason()
		s.mu.Lock()
		s.state = stateEnded
		s.mu.Unlock()
		s.log.Info("remote session ended before it became active", slog.String("reason", reason))
		h.finalStatus(s, protocol.SessionEnded, reason)
		return true
	}

	// ---- 1. consent ----
	noUser := false
	switch s.start.Consent {
	case protocol.ConsentRequire:
		timeout := time.Duration(s.start.ConsentTimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = defaultConsentTimeout
		}
		h.status(s.ctx, s.id, protocol.SessionPendingConsent, "")
		asked0 := time.Now()
		yes, asked, err := h.ui.Confirm(s.ctx, consentQuestion(s, timeout))
		elapsed := time.Since(asked0)
		if endedEarly() {
			return
		}
		switch {
		case err != nil:
			s.log.Error("consent prompt failed", slog.Any("error", err))
			fail(protocol.SessionFailed, ReasonConsentPromptFailed)
			return
		case !asked:
			present, perr := h.userPresent(s.ctx)
			if endedEarly() {
				return
			}
			if present {
				// Somebody is logged in but cannot be asked (text-only
				// login, no dialog tool): "require" cannot be honoured.
				s.log.Warn("a user is logged in but cannot be prompted; consent is required", slog.Any("error", perr))
				fail(protocol.SessionFailed, ReasonConsentUnavailable)
				return
			}
			noUser = true
			s.log.Info("nobody is logged in: no one to ask for consent")
		case !yes && elapsed >= timeout:
			fail(protocol.SessionDenied, ReasonTimeout)
			return
		case !yes:
			fail(protocol.SessionDenied, ReasonUserDenied)
			return
		default:
			s.log.Info("the user allowed the remote session")
		}
	case protocol.ConsentNotify:
		nctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		err := h.ui.Notify(nctx, "Remote support session",
			fmt.Sprintf("%s is starting a remote support session on this computer.\nType of access: %s.", s.requestedBy, kindLabel(s.kind)))
		cancel()
		if endedEarly() {
			return
		}
		if err != nil {
			// The indicator below is shown in any case.
			s.log.Warn("could not show the session notification", slog.Any("error", err))
		}
	}

	// ---- 2. visible indicator (every mode, including "none") ----
	title, message := indicatorText(s)
	stopIndicator, userEnded, shown, err := h.ui.ShowIndicator(s.ctx, title, message)
	if stopIndicator == nil {
		stopIndicator = func() {}
	}
	if endedEarly() {
		stopIndicator()
		return
	}
	if !shown {
		present, perr := h.userPresent(s.ctx)
		if err != nil || present {
			stopIndicator()
			if endedEarly() {
				return
			}
			s.log.Error("the session indicator cannot be shown to the logged-in user", slog.Any("error", errors.Join(err, perr)))
			fail(protocol.SessionFailed, ReasonIndicatorUnavailable)
			return
		}
		noUser = true
	}
	indicatorDone := make(chan struct{})
	go h.keepIndicator(s, indicatorDone, stopIndicator, userEnded, shown)
	// From here on the indicator goroutine owns the indicator; it removes it
	// when the session's context ends.
	waitIndicator := func() {
		s.cancel()
		<-indicatorDone
	}

	// ---- 3. start ----
	var term Terminal
	var out *pump
	sendCtx, stopSending := context.WithCancel(context.Background())
	defer stopSending()
	if s.kind == protocol.SessionKindTerminal {
		spec := TerminalSpec{Cols: s.start.Terminal.Cols, Rows: s.start.Terminal.Rows}
		if s.start.Terminal.RunAs == protocol.RunAsUser {
			u, uerr := h.plat.ConsoleUser(s.ctx)
			if uerr != nil {
				waitIndicator()
				if errors.Is(uerr, platform.ErrNoConsoleUser) {
					fail(protocol.SessionFailed, "no logged-in user")
				} else {
					fail(protocol.SessionFailed, "terminal: "+uerr.Error())
				}
				return
			}
			spec.AsUser = u
		}
		t, terr := h.opts.StartTerminal(s.ctx, spec)
		if terr != nil {
			waitIndicator()
			var ue *unsupportedError
			if errors.As(terr, &ue) {
				fail(protocol.SessionFailed, ue.Error())
			} else {
				fail(protocol.SessionFailed, "terminal: "+terr.Error())
			}
			return
		}
		term = t
		// Replay protection of session.input starts here; a session id can
		// be opened only once.
		if oerr := h.seq.Open(s.id); oerr != nil {
			term.Kill()
			_ = term.Close()
			waitIndicator()
			fail(protocol.SessionFailed, ReasonSessionIDReused)
			return
		}
		s.mu.Lock()
		s.term = term
		s.inputs = make(chan []byte, inputQueue)
		s.mu.Unlock()
		out = startPump(sendCtx, s.id, term, h.send, h.opts.FlushInterval)
		go writeInputs(s, term)
	}

	s.mu.Lock()
	if s.ctx.Err() == nil {
		s.state = stateActive
	}
	s.mu.Unlock()
	activeReason := ""
	if noUser {
		activeReason = ReasonNoUser
	}
	if s.ctx.Err() == nil {
		s.log.Info("remote session active", slog.Bool("user_logged_in", !noUser), slog.Int("shell_pid", pidOf(term)))
		h.status(s.ctx, s.id, protocol.SessionActive, activeReason)
	}

	// ---- 4. wait for the end ----
	maxTimer := time.NewTimer(h.opts.MaxDuration)
	defer maxTimer.Stop()
	var shellExited <-chan struct{}
	if term != nil {
		shellExited = term.Done()
	}
	select {
	case <-s.ctx.Done():
	case <-shellExited:
		s.end(ReasonTerminalExited)
	case <-maxTimer.C:
		s.end(ReasonMaxDuration)
	}
	reason := s.reason()

	// ---- 5. tear down (always, in this order) ----
	s.mu.Lock()
	s.state = stateEnded
	s.mu.Unlock()
	if term != nil {
		// No more input is accepted for this session id, ever.
		h.seq.Close(s.id)
		// Kill the shell and everything started from it.
		term.Kill()
		if reason == ReasonConnectionLost {
			out.stop()
			stopSending()
		} else {
			// Deliver what the shell printed last, briefly.
			out.waitDelivered(2 * time.Second)
			out.stop()
			stopSending()
		}
		_ = term.Close()
		<-out.senderDone
	}
	<-indicatorDone
	s.log.Info("remote session ended", slog.String("reason", reason))
	h.finalStatus(s, protocol.SessionEnded, reason)
}

func pidOf(t Terminal) int {
	if t == nil {
		return 0
	}
	return t.PID()
}

// writeInputs feeds queued input to the shell; a shell that does not read
// blocks this goroutine, not the control connection.
func writeInputs(s *session, term Terminal) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case data := <-s.inputs:
			if _, err := term.Write(data); err != nil {
				return
			}
		}
	}
}

// keepIndicator owns the indicator for the whole session: it ends the
// session when the user chooses "End session" (or when the indicator can no
// longer be shown), keeps looking for a user when the session started with
// nobody logged in, and removes the indicator when the session is over.
func (h *Handler) keepIndicator(s *session, done chan<- struct{}, stop func(), userEnded <-chan struct{}, shown bool) {
	defer close(done)
	title, message := indicatorText(s)
	for {
		if shown {
			select {
			case <-userEnded:
				s.log.Info("the session was ended from the indicator on the device")
				s.end(ReasonEndedLocally)
			case <-s.ctx.Done():
			}
			stop()
			return
		}
		stop()
		t := time.NewTimer(h.opts.IndicatorRetry)
		select {
		case <-s.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		var err error
		stop, userEnded, shown, err = h.ui.ShowIndicator(s.ctx, title, message)
		if stop == nil {
			stop = func() {}
		}
		if s.ctx.Err() != nil {
			stop()
			return
		}
		if !shown {
			present, perr := h.userPresent(s.ctx)
			if s.ctx.Err() != nil {
				stop()
				return
			}
			if err != nil || present {
				// Somebody logged in and cannot be shown the indicator.
				s.log.Error("the session indicator cannot be shown to the user who logged in; ending the session",
					slog.Any("error", errors.Join(err, perr)))
				stop()
				s.end(ReasonIndicatorUnavailable)
				return
			}
		} else {
			s.log.Info("a user logged in: session indicator shown")
		}
	}
}
