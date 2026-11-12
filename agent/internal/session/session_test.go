package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

const wait = 10 * time.Second

// ---- fakes ----

type sent struct {
	typ     string
	payload any
}

// fakeSender records messages. While blocked it behaves like the agent
// without a connection: Send waits for ctx.
type fakeSender struct {
	mu      sync.Mutex
	msgs    []sent
	changed chan struct{}
	blocked bool
}

func newSender() *fakeSender { return &fakeSender{changed: make(chan struct{})} }

func (f *fakeSender) Send(ctx context.Context, typ string, payload any) error {
	f.mu.Lock()
	if f.blocked {
		f.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	// Round-trip through JSON like the real sender.
	raw, err := json.Marshal(payload)
	if err != nil {
		f.mu.Unlock()
		return err
	}
	var v any
	switch typ {
	case protocol.TypeSessionStatus:
		var s protocol.SessionStatus
		_ = json.Unmarshal(raw, &s)
		v = s
	case protocol.TypeSessionOutput:
		var o protocol.SessionOutput
		_ = json.Unmarshal(raw, &o)
		v = o
	}
	f.msgs = append(f.msgs, sent{typ, v})
	close(f.changed)
	f.changed = make(chan struct{})
	f.mu.Unlock()
	return ctx.Err()
}

func (f *fakeSender) block(b bool) {
	f.mu.Lock()
	f.blocked = b
	f.mu.Unlock()
}

func (f *fakeSender) statuses(id string) []protocol.SessionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []protocol.SessionStatus
	for _, m := range f.msgs {
		if s, ok := m.payload.(protocol.SessionStatus); ok && s.SessionID == id {
			out = append(out, s)
		}
	}
	return out
}

// output returns the concatenated terminal bytes of a session and checks
// that sequence numbers count from 1 and chunks respect the size limit.
func (f *fakeSender) output(t *testing.T, id string) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var buf bytes.Buffer
	var next uint64 = 1
	for _, m := range f.msgs {
		o, ok := m.payload.(protocol.SessionOutput)
		if !ok || o.SessionID != id {
			continue
		}
		if o.Seq != next {
			t.Fatalf("session.output seq = %d, want %d", o.Seq, next)
		}
		next++
		data, err := base64.StdEncoding.DecodeString(o.Data)
		if err != nil {
			t.Fatalf("session.output data is not base64: %v", err)
		}
		if len(data) == 0 || len(data) > MaxOutputChunk {
			t.Fatalf("session.output chunk of %d bytes", len(data))
		}
		buf.Write(data)
	}
	return buf.Bytes()
}

func (f *fakeSender) outputCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, m := range f.msgs {
		if o, ok := m.payload.(protocol.SessionOutput); ok && o.SessionID == id {
			n++
		}
	}
	return n
}

func (f *fakeSender) await(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		ch := f.changed
		f.mu.Unlock()
		if cond() {
			return
		}
		select {
		case <-ch:
		case <-time.After(20 * time.Millisecond):
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s; statuses so far: %+v", what, f.allStatuses())
		}
	}
}

func (f *fakeSender) allStatuses() []protocol.SessionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []protocol.SessionStatus
	for _, m := range f.msgs {
		if s, ok := m.payload.(protocol.SessionStatus); ok {
			out = append(out, s)
		}
	}
	return out
}

// awaitState waits for a session.status with that state and returns it.
func (f *fakeSender) awaitState(t *testing.T, id, state string) protocol.SessionStatus {
	t.Helper()
	var found protocol.SessionStatus
	f.await(t, "session.status "+state, func() bool {
		for _, s := range f.statuses(id) {
			if s.State == state {
				found = s
				return true
			}
		}
		return false
	})
	return found
}

// fakeTerminal is an in-memory Terminal.
type fakeTerminal struct {
	mu      sync.Mutex
	input   bytes.Buffer
	sizes   [][2]int
	killed  int
	closed  int
	outR    *io.PipeReader
	outW    *io.PipeWriter
	done    chan struct{}
	exitOne sync.Once
}

func newFakeTerminal() *fakeTerminal {
	r, w := io.Pipe()
	return &fakeTerminal{outR: r, outW: w, done: make(chan struct{})}
}

func (t *fakeTerminal) Read(p []byte) (int, error) { return t.outR.Read(p) }
func (t *fakeTerminal) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.input.Write(p)
}
func (t *fakeTerminal) Resize(cols, rows int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sizes = append(t.sizes, [2]int{cols, rows})
	return nil
}
func (t *fakeTerminal) Done() <-chan struct{} { return t.done }
func (t *fakeTerminal) PID() int              { return 4242 }
func (t *fakeTerminal) exit() {
	t.exitOne.Do(func() {
		_ = t.outW.Close()
		close(t.done)
	})
}
func (t *fakeTerminal) Kill() {
	t.mu.Lock()
	t.killed++
	t.mu.Unlock()
	t.exit()
}
func (t *fakeTerminal) Close() error {
	t.mu.Lock()
	t.closed++
	t.mu.Unlock()
	return t.outR.Close()
}
func (t *fakeTerminal) typed() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.input.String()
}
func (t *fakeTerminal) counts() (killed, closed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.killed, t.closed
}

// seat is a Platform whose console user can change during a test.
type seat struct {
	platform.Fake
	mu   sync.Mutex
	user *platform.User
	err  error
}

func (s *seat) set(u *platform.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.user = u
}

func (s *seat) ConsoleUser(context.Context) (*platform.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.user == nil {
		return nil, platform.ErrNoConsoleUser
	}
	u := *s.user
	return &u, nil
}

var alice = &platform.User{Name: "alice", UID: "1000", GID: "1000", Home: "/home/alice"}

type fixture struct {
	t      *testing.T
	h      *Handler
	send   *fakeSender
	ui     *userui.Fake
	seat   *seat
	seq    *protocol.SeqTracker
	mu     sync.Mutex
	terms  []*fakeTerminal
	specs  []TerminalSpec
	ctx    context.Context
	cancel context.CancelFunc
}

func newFixture(t *testing.T, mut func(*Options)) *fixture {
	t.Helper()
	fx := &fixture{t: t, send: newSender(), ui: userui.NewFake(), seat: &seat{user: alice}, seq: protocol.NewSeqTracker()}
	opts := Options{
		IndicatorRetry: 20 * time.Millisecond,
		StartTerminal: func(_ context.Context, spec TerminalSpec) (Terminal, error) {
			term := newFakeTerminal()
			fx.mu.Lock()
			fx.terms = append(fx.terms, term)
			fx.specs = append(fx.specs, spec)
			fx.mu.Unlock()
			return term, nil
		},
	}
	if mut != nil {
		mut(&opts)
	}
	fx.h = New(agentcore.Env{Sender: fx.send, Seq: fx.seq, Platform: fx.seat, Log: logging.Discard()}, fx.ui, opts)
	// ctx plays the control connection's context.
	fx.ctx, fx.cancel = context.WithCancel(context.Background())
	t.Cleanup(func() {
		fx.cancel()
		fx.h.ConnectionLost()
	})
	return fx
}

func (fx *fixture) term(i int) *fakeTerminal {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	if i >= len(fx.terms) {
		return nil
	}
	return fx.terms[i]
}

func startMsg(kind, consent string) protocol.SessionStart {
	s := protocol.SessionStart{
		SessionID:             protocol.NewID(),
		Kind:                  kind,
		Consent:               consent,
		ConsentTimeoutSeconds: 60,
		RequestedBy:           "Jane Doe (Example IT)",
	}
	if kind == protocol.SessionKindTerminal {
		s.Terminal = &protocol.TerminalOptions{Cols: 120, Rows: 30, RunAs: protocol.RunAsSystem}
	}
	return s
}

func states(list []protocol.SessionStatus) string {
	parts := make([]string, 0, len(list))
	for _, s := range list {
		if s.Reason != "" {
			parts = append(parts, s.State+"("+s.Reason+")")
		} else {
			parts = append(parts, s.State)
		}
	}
	return strings.Join(parts, " ")
}

func (fx *fixture) waitGone(id string) {
	fx.t.Helper()
	deadline := time.Now().Add(wait)
	for {
		fx.h.mu.Lock()
		_, there := fx.h.sessions[id]
		fx.h.mu.Unlock()
		if !there {
			return
		}
		if time.Now().After(deadline) {
			fx.t.Fatalf("session %s was not torn down", id)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- consent and indicator ----

func TestConsentMatrix(t *testing.T) {
	type tc struct {
		name    string
		consent string
		// user sitting at the device and how the UI behaves
		user     bool
		answer   bool
		timesOut bool
		// expectations
		want          string
		active        bool
		questions     int
		notifications int
		indicators    int
	}
	cases := []tc{
		{name: "none/user", consent: "none", user: true, want: "active", active: true, indicators: 1},
		{name: "none/nobody", consent: "none", user: false, want: "active(no_user_logged_in)", active: true, indicators: 1},
		{name: "notify/user", consent: "notify", user: true, want: "active", active: true, notifications: 1, indicators: 1},
		{name: "notify/nobody", consent: "notify", user: false, want: "active(no_user_logged_in)", active: true, notifications: 1, indicators: 1},
		{name: "require/yes", consent: "require", user: true, answer: true, want: "pending_consent active", active: true, questions: 1, indicators: 1},
		{name: "require/no", consent: "require", user: true, answer: false, want: "pending_consent denied(user_denied)", questions: 1},
		{name: "require/timeout", consent: "require", user: true, timesOut: true, want: "pending_consent denied(timeout)", questions: 1},
		{name: "require/nobody", consent: "require", user: false, want: "pending_consent active(no_user_logged_in)", active: true, questions: 1, indicators: 1},
	}
	for _, kind := range []string{protocol.SessionKindTerminal, protocol.SessionKindFiles, protocol.SessionKindDesktop} {
		for _, c := range cases {
			t.Run(kind+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				fx := newFixture(t, nil)
				if !c.user {
					fx.seat.set(nil)
				}
				fx.ui.Set(func(f *userui.Fake) {
					f.Answer, f.Asked, f.Shown, f.TimesOut = c.answer, c.user, c.user, c.timesOut
				})
				msg := startMsg(kind, c.consent)
				msg.ConsentTimeoutSeconds = 1
				fx.h.Start(fx.ctx, msg)

				final := protocol.SessionActive
				if !c.active {
					final = protocol.SessionDenied
				}
				fx.send.awaitState(t, msg.SessionID, final)
				if got := states(fx.send.statuses(msg.SessionID)); got != c.want {
					t.Errorf("statuses = %q, want %q", got, c.want)
				}
				gotKind, ok := fx.h.ActiveSession(msg.SessionID)
				if ok != c.active || (ok && gotKind != kind) {
					t.Errorf("ActiveSession = %q, %v", gotKind, ok)
				}
				if !c.active {
					fx.waitGone(msg.SessionID)
				}
				notes, questions, indicators, _ := fx.ui.Snapshot()
				if len(questions) != c.questions || len(notes) != c.notifications || len(indicators) < c.indicators || (c.indicators == 0 && len(indicators) != 0) {
					t.Errorf("questions=%d notifications=%d indicators=%d, want %d/%d/%d", len(questions), len(notes), len(indicators), c.questions, c.notifications, c.indicators)
				}
				if c.questions == 1 {
					q := questions[0]
					if q.DefaultYes || q.Timeout != time.Second || q.YesLabel != "Allow" || q.NoLabel != "Deny" || !strings.Contains(q.Message, "Jane Doe (Example IT)") {
						t.Errorf("question = %+v (must default to Deny)", q)
					}
				}
				for _, text := range append(notes, indicators...) {
					if !strings.Contains(text, "Jane Doe (Example IT)") {
						t.Errorf("the user is not told who is connecting: %q", text)
					}
				}
				if c.indicators > 0 && !strings.Contains(indicators[0], "Remote session active: Jane Doe (Example IT)") {
					t.Errorf("indicator text = %q", indicators[0])
				}
				if kind == protocol.SessionKindTerminal {
					if started := fx.term(0) != nil; started != c.active {
						t.Errorf("shell started = %v for an %s session", started, final)
					}
				}
			})
		}
	}
}

func TestRequireFailsClosedWhenTheUserCannotBeAsked(t *testing.T) {
	// A user is logged in, but no prompt can be shown (text-only login).
	fx := newFixture(t, nil)
	fx.ui.Set(func(f *userui.Fake) { f.Asked = false })
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentRequire)
	fx.h.Start(fx.ctx, msg)
	st := fx.send.awaitState(t, msg.SessionID, protocol.SessionFailed)
	if st.Reason != ReasonConsentUnavailable {
		t.Errorf("reason = %q", st.Reason)
	}
	fx.waitGone(msg.SessionID)
	if fx.term(0) != nil {
		t.Error("a shell was started without consent")
	}

	// The prompt itself failed.
	fx = newFixture(t, nil)
	fx.ui.Set(func(f *userui.Fake) { f.ConfirmErr = errors.New("no display") })
	msg = startMsg(protocol.SessionKindFiles, protocol.ConsentRequire)
	fx.h.Start(fx.ctx, msg)
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionFailed); st.Reason != ReasonConsentPromptFailed {
		t.Errorf("reason = %q", st.Reason)
	}

	// Whether somebody is logged in cannot be determined: fail closed.
	fx = newFixture(t, nil)
	fx.ui.Set(func(f *userui.Fake) { f.Asked = false })
	fx.seat.err = errors.New("logind unavailable")
	msg = startMsg(protocol.SessionKindFiles, protocol.ConsentRequire)
	fx.h.Start(fx.ctx, msg)
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionFailed); st.Reason != ReasonConsentUnavailable {
		t.Errorf("reason = %q", st.Reason)
	}
}

func TestNoSessionWithoutIndicatorForALoggedInUser(t *testing.T) {
	for _, consent := range []string{protocol.ConsentNone, protocol.ConsentNotify, protocol.ConsentRequire} {
		for _, withErr := range []bool{false, true} {
			fx := newFixture(t, nil)
			fx.ui.Set(func(f *userui.Fake) {
				f.Shown = false
				if withErr {
					f.IndicatorErr = errors.New("cannot open display")
				}
			})
			msg := startMsg(protocol.SessionKindTerminal, consent)
			fx.h.Start(fx.ctx, msg)
			st := fx.send.awaitState(t, msg.SessionID, protocol.SessionFailed)
			if st.Reason != ReasonIndicatorUnavailable {
				t.Errorf("%s: reason = %q", consent, st.Reason)
			}
			fx.waitGone(msg.SessionID)
			if _, ok := fx.h.ActiveSession(msg.SessionID); ok || fx.term(0) != nil {
				t.Errorf("%s: session went on without a visible indicator", consent)
			}
		}
	}
}

func TestIndicatorStoppedWhenSessionEnds(t *testing.T) {
	for _, consent := range []string{protocol.ConsentNone, protocol.ConsentNotify, protocol.ConsentRequire} {
		fx := newFixture(t, nil)
		msg := startMsg(protocol.SessionKindTerminal, consent)
		fx.h.Start(fx.ctx, msg)
		fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
		if err := fx.seq.Accept(msg.SessionID, 1); err != nil {
			t.Fatalf("session.input replay protection was not opened: %v", err)
		}
		_, _, indicators, stopped := fx.ui.Snapshot()
		if len(indicators) != 1 || stopped != 0 {
			t.Fatalf("%s: indicators=%d stopped=%d while active", consent, len(indicators), stopped)
		}

		fx.h.End(fx.ctx, protocol.SessionEnd{SessionID: msg.SessionID, Reason: "technician closed the tab"})
		st := fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded)
		if st.Reason != ReasonEndedByServer {
			t.Errorf("reason = %q", st.Reason)
		}
		// By the time "ended" is reported everything is already gone.
		if _, _, _, stopped := fx.ui.Snapshot(); stopped != 1 {
			t.Errorf("%s: indicator stopped %d times", consent, stopped)
		}
		if killed, closed := fx.term(0).counts(); killed != 1 || closed != 1 {
			t.Errorf("%s: terminal killed=%d closed=%d", consent, killed, closed)
		}
		if _, ok := fx.h.ActiveSession(msg.SessionID); ok {
			t.Error("still active after session.end")
		}
		if err := fx.seq.Accept(msg.SessionID, 2); !errors.Is(err, protocol.ErrSessionNotActive) {
			t.Errorf("input after the end: %v", err)
		}
		// The same session id can never be started again.
		fx.waitGone(msg.SessionID)
		fx.h.Start(fx.ctx, msg)
		fx.send.await(t, "refusal of the reused id", func() bool {
			list := fx.send.statuses(msg.SessionID)
			return list[len(list)-1].State == protocol.SessionFailed
		})
		if list := fx.send.statuses(msg.SessionID); list[len(list)-1].Reason != ReasonSessionIDReused {
			t.Errorf("reused id: %+v", list[len(list)-1])
		}
	}
}

func TestUserEndsSessionLocally(t *testing.T) {
	for _, kind := range []string{protocol.SessionKindTerminal, protocol.SessionKindFiles, protocol.SessionKindDesktop} {
		fx := newFixture(t, nil)
		msg := startMsg(kind, protocol.ConsentNone)
		fx.h.Start(fx.ctx, msg)
		fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)

		fx.ui.UserEndsSession()
		st := fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded)
		if st.Reason != ReasonEndedLocally {
			t.Errorf("%s: reason = %q", kind, st.Reason)
		}
		if _, ok := fx.h.ActiveSession(msg.SessionID); ok {
			t.Errorf("%s: still active", kind)
		}
		if term := fx.term(0); term != nil {
			if killed, _ := term.counts(); killed != 1 {
				t.Errorf("shell not killed")
			}
		}
		if _, _, _, stopped := fx.ui.Snapshot(); stopped != 1 {
			t.Errorf("indicator stopped %d times", stopped)
		}
	}
}

func TestConnectionLostEndsEverything(t *testing.T) {
	fx := newFixture(t, nil)
	var ids []string
	for _, kind := range []string{protocol.SessionKindTerminal, protocol.SessionKindFiles, protocol.SessionKindDesktop} {
		msg := startMsg(kind, protocol.ConsentNone)
		fx.h.Start(fx.ctx, msg)
		fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
		ids = append(ids, msg.SessionID)
	}
	// A fourth one is still waiting for the user's answer.
	fx.ui.Set(func(f *userui.Fake) { f.TimesOut = true })
	pending := startMsg(protocol.SessionKindTerminal, protocol.ConsentRequire)
	fx.h.Start(fx.ctx, pending)
	fx.send.awaitState(t, pending.SessionID, protocol.SessionPendingConsent)

	// The connection drops: the sender blocks like the real one.
	fx.send.block(true)
	started := time.Now()
	fx.h.ConnectionLost()
	if d := time.Since(started); d > 5*time.Second {
		t.Errorf("ConnectionLost took %v", d)
	}
	// Everything is torn down by the time ConnectionLost returns.
	fx.h.mu.Lock()
	left := len(fx.h.sessions)
	fx.h.mu.Unlock()
	if left != 0 {
		t.Errorf("%d sessions survived the connection", left)
	}
	for _, id := range append(ids, pending.SessionID) {
		if _, ok := fx.h.ActiveSession(id); ok {
			t.Errorf("session %s still active", id)
		}
	}
	if killed, closed := fx.term(0).counts(); killed != 1 || closed != 1 {
		t.Errorf("terminal killed=%d closed=%d", killed, closed)
	}
	if fx.term(1) != nil {
		t.Error("the session that was waiting for consent started a shell")
	}
	if _, _, indicators, stopped := fx.ui.Snapshot(); stopped != len(indicators) || len(indicators) != 3 {
		t.Errorf("indicators=%d stopped=%d", len(indicators), stopped)
	}
	if err := fx.seq.Accept(ids[0], 1); !errors.Is(err, protocol.ErrSessionNotActive) {
		t.Errorf("input accepted after connection loss: %v", err)
	}
}

func TestConnectionContextEndsSessions(t *testing.T) {
	// Even without the ConnectionLost call, the connection's context ending
	// takes the session down.
	fx := newFixture(t, nil)
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	fx.h.Start(fx.ctx, msg)
	fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
	fx.cancel()
	fx.waitGone(msg.SessionID)
	if killed, _ := fx.term(0).counts(); killed != 1 {
		t.Error("shell not killed")
	}
	for _, s := range fx.send.statuses(msg.SessionID) {
		if s.State == protocol.SessionEnded {
			t.Errorf("unexpected status on a dead connection: %+v", s)
		}
	}
}

func TestEndWhileWaitingForConsent(t *testing.T) {
	fx := newFixture(t, nil)
	fx.ui.Set(func(f *userui.Fake) { f.TimesOut = true })
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentRequire)
	fx.h.Start(fx.ctx, msg)
	fx.send.awaitState(t, msg.SessionID, protocol.SessionPendingConsent)
	if _, ok := fx.h.ActiveSession(msg.SessionID); ok {
		t.Error("a session waiting for consent must not be active")
	}
	fx.h.End(fx.ctx, protocol.SessionEnd{SessionID: msg.SessionID})
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded); st.Reason != ReasonEndedByServer {
		t.Errorf("reason = %q", st.Reason)
	}
	fx.waitGone(msg.SessionID)
	if _, _, indicators, _ := fx.ui.Snapshot(); len(indicators) != 0 || fx.term(0) != nil {
		t.Error("something started although consent was never given")
	}
}

func TestMaxSessionsAndDuplicates(t *testing.T) {
	fx := newFixture(t, nil)
	var first protocol.SessionStart
	for i := 0; i < MaxSessions; i++ {
		msg := startMsg(protocol.SessionKindFiles, protocol.ConsentNone)
		if i == 0 {
			first = msg
		}
		fx.h.Start(fx.ctx, msg)
		fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
	}
	// A duplicate of an active session is ignored.
	fx.h.Start(fx.ctx, first)
	extra := startMsg(protocol.SessionKindFiles, protocol.ConsentNone)
	fx.h.Start(fx.ctx, extra)
	if st := fx.send.awaitState(t, extra.SessionID, protocol.SessionFailed); st.Reason != ReasonTooManySessions {
		t.Errorf("reason = %q", st.Reason)
	}
	if got := states(fx.send.statuses(first.SessionID)); got != "active" {
		t.Errorf("duplicate start changed the session: %q", got)
	}
	if _, _, indicators, _ := fx.ui.Snapshot(); len(indicators) != MaxSessions {
		t.Errorf("indicators = %d", len(indicators))
	}
	// Ending one makes room again.
	fx.h.End(fx.ctx, protocol.SessionEnd{SessionID: first.SessionID})
	fx.send.awaitState(t, first.SessionID, protocol.SessionEnded)
	fx.waitGone(first.SessionID)
	again := startMsg(protocol.SessionKindFiles, protocol.ConsentNone)
	fx.h.Start(fx.ctx, again)
	fx.send.awaitState(t, again.SessionID, protocol.SessionActive)
}

func TestMalformedStartRejected(t *testing.T) {
	cases := map[string]func(*protocol.SessionStart){
		"kind":               func(s *protocol.SessionStart) { s.Kind = "camera" },
		"empty kind":         func(s *protocol.SessionStart) { s.Kind = "" },
		"consent":            func(s *protocol.SessionStart) { s.Consent = "silent" },
		"negative timeout":   func(s *protocol.SessionStart) { s.ConsentTimeoutSeconds = -1 },
		"huge timeout":       func(s *protocol.SessionStart) { s.ConsentTimeoutSeconds = 601 },
		"no requestedBy":     func(s *protocol.SessionStart) { s.RequestedBy = "" },
		"long requestedBy":   func(s *protocol.SessionStart) { s.RequestedBy = strings.Repeat("x", 257) },
		"hidden requestedBy": func(s *protocol.SessionStart) { s.RequestedBy = "\x1b\u202e\u200b\n" },
		"no terminal":        func(s *protocol.SessionStart) { s.Terminal = nil },
		"zero cols":          func(s *protocol.SessionStart) { s.Terminal.Cols = 0 },
		"huge rows":          func(s *protocol.SessionStart) { s.Terminal.Rows = 1001 },
		"runAs":              func(s *protocol.SessionStart) { s.Terminal.RunAs = "administrator" },
	}
	for name, mutate := range cases {
		fx := newFixture(t, nil)
		msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
		mutate(&msg)
		fx.h.Start(fx.ctx, msg)
		st := fx.send.awaitState(t, msg.SessionID, protocol.SessionFailed)
		if st.Reason == "" {
			t.Errorf("%s: no reason", name)
		}
		if _, _, indicators, _ := fx.ui.Snapshot(); len(indicators) != 0 || fx.term(0) != nil {
			t.Errorf("%s: something started", name)
		}
	}
	// An invalid session id gets no answer at all.
	fx := newFixture(t, nil)
	msg := startMsg(protocol.SessionKindFiles, protocol.ConsentNone)
	msg.SessionID = "../../etc"
	fx.h.Start(fx.ctx, msg)
	time.Sleep(30 * time.Millisecond)
	if n := len(fx.send.allStatuses()); n != 0 {
		t.Errorf("statuses for an invalid id: %d", n)
	}
}

func TestRequestedByIsCleanedBeforeItIsShown(t *testing.T) {
	if got := CleanRequestedBy("  Mallory\x1b[2J\u202e (IT)\r\n\tSYSTEM\x00  "); got != "Mallory[2J (IT) SYSTEM" {
		t.Errorf("CleanRequestedBy = %q", got)
	}
	if got := CleanRequestedBy(strings.Repeat("é", 200)); len(got) > maxRequestedByShown || !strings.HasPrefix(got, "ééé") {
		t.Errorf("cap: %d bytes", len(got))
	}
	fx := newFixture(t, nil)
	msg := startMsg(protocol.SessionKindFiles, protocol.ConsentRequire)
	msg.RequestedBy = "Eve\u202e\x07\nWindows Update"
	fx.h.Start(fx.ctx, msg)
	fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
	_, questions, indicators, _ := fx.ui.Snapshot()
	for _, text := range []string{questions[0].Message, indicators[0]} {
		if strings.ContainsAny(text, "\u202e\x07") || !strings.Contains(text, "Eve Windows Update") {
			t.Errorf("text shown to the user = %q", text)
		}
	}
}

func TestIndicatorAppearsWhenAUserLogsInLater(t *testing.T) {
	fx := newFixture(t, nil)
	fx.seat.set(nil)
	fx.ui.Set(func(f *userui.Fake) { f.Asked, f.Shown = false, false })
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentRequire)
	fx.h.Start(fx.ctx, msg)
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionActive); st.Reason != ReasonNoUser {
		t.Errorf("reason = %q", st.Reason)
	}
	// Somebody logs in while the session is running.
	fx.seat.set(alice)
	fx.ui.Set(func(f *userui.Fake) { f.Asked, f.Shown = true, true })
	time.Sleep(100 * time.Millisecond)
	if _, _, indicators, _ := fx.ui.Snapshot(); len(indicators) < 2 {
		t.Fatalf("the indicator was not shown to the user who logged in (%d attempts)", len(indicators))
	}
	// ... and can end the session.
	fx.ui.UserEndsSession()
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded); st.Reason != ReasonEndedLocally {
		t.Errorf("reason = %q", st.Reason)
	}
}

func TestSessionEndsWhenLateIndicatorCannotBeShown(t *testing.T) {
	fx := newFixture(t, nil)
	fx.seat.set(nil)
	fx.ui.Set(func(f *userui.Fake) { f.Shown = false })
	msg := startMsg(protocol.SessionKindFiles, protocol.ConsentNone)
	fx.h.Start(fx.ctx, msg)
	fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
	// A user logs in but the indicator still cannot be shown.
	fx.seat.set(alice)
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded); st.Reason != ReasonIndicatorUnavailable {
		t.Errorf("reason = %q", st.Reason)
	}
}

func TestMaxDuration(t *testing.T) {
	fx := newFixture(t, func(o *Options) { o.MaxDuration = 80 * time.Millisecond })
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	fx.h.Start(fx.ctx, msg)
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded); st.Reason != ReasonMaxDuration {
		t.Errorf("reason = %q", st.Reason)
	}
	if killed, _ := fx.term(0).counts(); killed != 1 {
		t.Error("shell not killed")
	}
	if h := New(agentcore.Env{}, userui.NewFake(), Options{MaxDuration: 48 * time.Hour}); h.opts.MaxDuration != 12*time.Hour {
		t.Errorf("the 12 hour maximum can be raised: %v", h.opts.MaxDuration)
	}
}

// ---- terminal plumbing (fake terminal) ----

func input(id, data string) protocol.SessionInput {
	return protocol.SessionInput{SessionID: id, Kind: protocol.SessionInputData, Data: base64.StdEncoding.EncodeToString([]byte(data))}
}

func TestTerminalInputOutputAndExit(t *testing.T) {
	fx := newFixture(t, nil)
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	msg.Terminal.RunAs = protocol.RunAsUser
	fx.h.Start(fx.ctx, msg)
	fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
	term := fx.term(0)
	fx.mu.Lock()
	spec := fx.specs[0]
	fx.mu.Unlock()
	if spec.Cols != 120 || spec.Rows != 30 || spec.AsUser == nil || spec.AsUser.Name != "alice" {
		t.Errorf("terminal spec = %+v", spec)
	}

	fx.h.Input(fx.ctx, input(msg.SessionID, "ls -la\n"))
	fx.h.Input(fx.ctx, protocol.SessionInput{SessionID: msg.SessionID, Kind: protocol.SessionInputResize, Cols: 200, Rows: 50})
	fx.h.Input(fx.ctx, protocol.SessionInput{SessionID: msg.SessionID, Kind: protocol.SessionInputResize, Cols: 0, Rows: 50})
	fx.h.Input(fx.ctx, protocol.SessionInput{SessionID: msg.SessionID, Kind: protocol.SessionInputData, Data: "!!not base64!!"})
	fx.h.Input(fx.ctx, input(protocol.NewID(), "for nobody\n"))
	fx.send.await(t, "input to reach the shell", func() bool { return term.typed() == "ls -la\n" })
	term.mu.Lock()
	sizes := append([][2]int(nil), term.sizes...)
	term.mu.Unlock()
	if len(sizes) != 1 || sizes[0] != [2]int{200, 50} {
		t.Errorf("resizes = %v", sizes)
	}

	// Output: a burst larger than one chunk arrives complete, in order, in
	// chunks of at most 32 KiB.
	big := bytes.Repeat([]byte("0123456789abcdef"), 5000) // 80 KiB
	go func() {
		_, _ = term.outW.Write([]byte("hello "))
		_, _ = term.outW.Write([]byte("world\r\n"))
		_, _ = term.outW.Write(big)
	}()
	want := append([]byte("hello world\r\n"), big...)
	fx.send.await(t, "all output", func() bool { return len(fx.send.output(t, msg.SessionID)) == len(want) })
	if !bytes.Equal(fx.send.output(t, msg.SessionID), want) {
		t.Error("output differs from what the shell printed")
	}

	// The shell exits: the session ends by itself.
	go func() { _, _ = term.outW.Write([]byte("logout\r\n")) }()
	fx.send.await(t, "last output", func() bool { return bytes.HasSuffix(fx.send.output(t, msg.SessionID), []byte("logout\r\n")) })
	term.exit()
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded); st.Reason != ReasonTerminalExited {
		t.Errorf("reason = %q", st.Reason)
	}
	if _, _, _, stopped := fx.ui.Snapshot(); stopped != 1 {
		t.Errorf("indicator stopped %d times", stopped)
	}
}

func TestSmallWritesAreCoalesced(t *testing.T) {
	fx := newFixture(t, func(o *Options) { o.FlushInterval = 150 * time.Millisecond })
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	fx.h.Start(fx.ctx, msg)
	fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
	term := fx.term(0)
	for i := 0; i < 50; i++ {
		_, _ = term.outW.Write([]byte("x"))
	}
	fx.send.await(t, "output", func() bool { return len(fx.send.output(t, msg.SessionID)) == 50 })
	if n := fx.send.outputCount(msg.SessionID); n > 3 {
		t.Errorf("50 one-byte writes became %d messages", n)
	}
}

func TestOutputBackPressure(t *testing.T) {
	// The server does not take output: the agent must stop reading from the
	// shell instead of buffering without bound.
	fx := newFixture(t, nil)
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	fx.h.Start(fx.ctx, msg)
	fx.send.awaitState(t, msg.SessionID, protocol.SessionActive)
	term := fx.term(0)
	fx.send.block(true)

	var written int
	var mu sync.Mutex
	go func() {
		chunk := make([]byte, 16<<10)
		for {
			if _, err := term.outW.Write(chunk); err != nil {
				return
			}
			mu.Lock()
			written += len(chunk)
			mu.Unlock()
		}
	}()
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	got := written
	mu.Unlock()
	if limit := (readQueue + 4) * MaxOutputChunk; got > limit {
		t.Errorf("agent buffered %d bytes of unsent output (limit %d)", got, limit)
	}
	// The stuck sender does not keep the session from ending.
	fx.send.block(false)
	fx.h.End(fx.ctx, protocol.SessionEnd{SessionID: msg.SessionID})
	fx.send.awaitState(t, msg.SessionID, protocol.SessionEnded)
}

func TestInputOnlyForActiveTerminals(t *testing.T) {
	fx := newFixture(t, nil)
	files := startMsg(protocol.SessionKindFiles, protocol.ConsentNone)
	fx.h.Start(fx.ctx, files)
	fx.send.awaitState(t, files.SessionID, protocol.SessionActive)
	fx.h.Input(fx.ctx, input(files.SessionID, "rm -rf /\n"))
	// Only terminal sessions take part in session.input replay protection.
	if err := fx.seq.Accept(files.SessionID, 1); !errors.Is(err, protocol.ErrSessionNotActive) {
		t.Errorf("a files session accepts session.input: %v", err)
	}

	term := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	fx.h.Start(fx.ctx, term)
	fx.send.awaitState(t, term.SessionID, protocol.SessionActive)
	fx.h.End(fx.ctx, protocol.SessionEnd{SessionID: term.SessionID})
	fx.send.awaitState(t, term.SessionID, protocol.SessionEnded)
	fx.h.Input(fx.ctx, input(term.SessionID, "late\n"))
	if got := fx.term(0).typed(); got != "" {
		t.Errorf("input reached a terminal: %q", got)
	}
	// Oversized input is dropped.
	big := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	fx.h.Start(fx.ctx, big)
	fx.send.awaitState(t, big.SessionID, protocol.SessionActive)
	fx.h.Input(fx.ctx, input(big.SessionID, strings.Repeat("A", MaxInputBytes+1)))
	fx.h.Input(fx.ctx, input(big.SessionID, "ok\n"))
	fx.send.await(t, "input", func() bool { return fx.term(1).typed() == "ok\n" })
}

func TestTerminalStartFailure(t *testing.T) {
	fx := newFixture(t, func(o *Options) {
		o.StartTerminal = func(context.Context, TerminalSpec) (Terminal, error) {
			return nil, &unsupportedError{what: "terminal as logged-in user"}
		}
	})
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	fx.h.Start(fx.ctx, msg)
	st := fx.send.awaitState(t, msg.SessionID, protocol.SessionFailed)
	if st.Reason != "not supported on this OS: terminal as logged-in user" {
		t.Errorf("reason = %q", st.Reason)
	}
	fx.waitGone(msg.SessionID)
	if _, _, indicators, stopped := fx.ui.Snapshot(); len(indicators) != 1 || stopped != 1 {
		t.Errorf("indicator left behind: shown=%d stopped=%d", len(indicators), stopped)
	}

	// runAs "user" with nobody logged in never falls back to a root shell.
	fx = newFixture(t, nil)
	fx.seat.set(nil)
	fx.ui.Set(func(f *userui.Fake) { f.Asked, f.Shown = false, false })
	msg = startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	msg.Terminal.RunAs = protocol.RunAsUser
	fx.h.Start(fx.ctx, msg)
	if st := fx.send.awaitState(t, msg.SessionID, protocol.SessionFailed); st.Reason != "no logged-in user" {
		t.Errorf("reason = %q", st.Reason)
	}
	if fx.term(0) != nil {
		t.Error("a shell was started")
	}
}

func TestKinds(t *testing.T) {
	h := New(agentcore.Env{}, userui.NewFake(), Options{})
	if got := strings.Join(h.Kinds(), ","); got != "terminal,files,desktop" {
		t.Errorf("kinds = %q", got)
	}
}
