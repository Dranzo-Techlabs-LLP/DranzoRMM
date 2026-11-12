//go:build !windows

package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
	"github.com/dranzo/dranzormm/agent/internal/transport"
	"github.com/dranzo/dranzormm/agent/internal/trust"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// End to end: the real agent core (mTLS WebSocket, signed-envelope
// verification, sequence tracking) with this package's session handler and a
// real pseudo-terminal, against the in-process fake server.

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type e2e struct {
	t      *testing.T
	srv    *testserver.Server
	ui     *userui.Fake
	logs   *lockedBuffer
	device string
}

func startE2E(t *testing.T) *e2e {
	t.Helper()
	srv, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	paths := config.ResolvePaths(filepath.Join(t.TempDir(), "data"))
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := trust.Install(paths.CAFile(), paths.TrustFile(), srv.CAPEM, srv.TrustKeys()); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveBootstrap(paths, &config.Bootstrap{ServerURL: srv.URL, Token: srv.Token}); err != nil {
		t.Fatal(err)
	}
	e := &e2e{t: t, srv: srv, ui: userui.NewFake(), logs: &lockedBuffer{}}
	agent, err := agentcore.New(agentcore.Options{
		Paths:           paths,
		Logger:          logging.NewWithWriter(e.logs, slog.LevelDebug),
		Platform:        &platform.Fake{ID: "machine-session-e2e", User: alice},
		Version:         "9.9.9-test",
		Backoff:         &transport.Backoff{Base: 20 * time.Millisecond, Cap: 200 * time.Millisecond},
		RenewFirstCheck: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	agent.SetSessionHandler(New(agent.Env(), e.ui, Options{}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("agent did not stop")
		}
	})
	if e.device, err = srv.AwaitDevice(20 * time.Second); err != nil {
		t.Fatalf("agent did not enroll: %v\n%s", err, e.logs.String())
	}
	if err := srv.AwaitConnected(e.device, 20*time.Second); err != nil {
		t.Fatalf("agent did not connect: %v\n%s", err, e.logs.String())
	}
	return e
}

func (e *e2e) await(from int, msgType string, match func(*protocol.Envelope) bool) *protocol.Envelope {
	e.t.Helper()
	env, err := e.srv.Await(e.device, from, 20*time.Second, func(env *protocol.Envelope) bool {
		return env.Type == msgType && (match == nil || match(env))
	})
	if err != nil {
		e.t.Fatalf("no %s message: %v\nagent log:\n%s", msgType, err, e.logs.String())
	}
	return env
}

func (e *e2e) awaitStatus(from int, sessionID, state string) protocol.SessionStatus {
	e.t.Helper()
	var st protocol.SessionStatus
	e.await(from, protocol.TypeSessionStatus, func(env *protocol.Envelope) bool {
		var s protocol.SessionStatus
		if json.Unmarshal(env.Payload, &s) != nil || s.SessionID != sessionID || s.State != state {
			return false
		}
		st = s
		return true
	})
	return st
}

func (e *e2e) awaitError(from int, refID string) protocol.ErrorPayload {
	e.t.Helper()
	var p protocol.ErrorPayload
	e.await(from, protocol.TypeError, func(env *protocol.Envelope) bool {
		var x protocol.ErrorPayload
		if json.Unmarshal(env.Payload, &x) != nil || x.RefID != refID {
			return false
		}
		p = x
		return true
	})
	return p
}

// output is the terminal output of a session received by the server so far.
func (e *e2e) output(sessionID string) string {
	var b strings.Builder
	var next uint64 = 1
	for _, env := range e.srv.Messages(e.device, 0) {
		if env.Type != protocol.TypeSessionOutput {
			continue
		}
		var o protocol.SessionOutput
		if json.Unmarshal(env.Payload, &o) != nil || o.SessionID != sessionID {
			continue
		}
		if o.Seq != next {
			e.t.Fatalf("session.output seq = %d, want %d", o.Seq, next)
		}
		next++
		data, err := base64.StdEncoding.DecodeString(o.Data)
		if err != nil {
			e.t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

func (e *e2e) expectOutput(sessionID, re string) string {
	e.t.Helper()
	rx := regexp.MustCompile(re)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if m := rx.FindStringSubmatch(e.output(sessionID)); m != nil {
			return m[len(m)-1]
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("output never matched %q: %q\nagent log:\n%s", re, e.output(sessionID), e.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *e2e) inputPayload(sessionID string, seq uint64, line string) protocol.SessionInput {
	now := time.Now().UTC()
	return protocol.SessionInput{
		DeviceID: e.device, SessionID: sessionID, Seq: seq, Kind: protocol.SessionInputData,
		Data:     base64.StdEncoding.EncodeToString([]byte(line)),
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
}

func (e *e2e) sendInput(sessionID string, seq uint64, line string) string {
	e.t.Helper()
	id, err := e.srv.SendSigned(e.device, protocol.TypeSessionInput, e.inputPayload(sessionID, seq, line))
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func envID(t *testing.T, data []byte) string {
	t.Helper()
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.ID
}

func TestEndToEndSignedTerminalSession(t *testing.T) {
	e := startE2E(t)

	caps := strings.Join(e.srv.Hello(e.device).Capabilities, ",")
	for _, want := range []string{"session.terminal", "session.files", "session.desktop"} {
		if !strings.Contains(caps, want) {
			t.Errorf("hello.capabilities lacks %s: %s", want, caps)
		}
	}

	sessionID := protocol.NewID()
	mark := e.srv.Mark(e.device)
	start := protocol.SessionStart{
		SignedCommon: testserver.Common(e.device),
		SessionID:    sessionID, Kind: protocol.SessionKindTerminal, Consent: protocol.ConsentRequire,
		ConsentTimeoutSeconds: 30, RequestedBy: "Jane Doe (Example IT)",
		Terminal: &protocol.TerminalOptions{Cols: 120, Rows: 30, RunAs: protocol.RunAsSystem},
	}
	if _, err := e.srv.SendSigned(e.device, protocol.TypeSessionStart, start); err != nil {
		t.Fatal(err)
	}
	e.awaitStatus(mark, sessionID, protocol.SessionPendingConsent)
	e.awaitStatus(mark, sessionID, protocol.SessionActive)
	_, questions, indicators, _ := e.ui.Snapshot()
	if len(questions) != 1 || len(indicators) != 1 || !strings.Contains(indicators[0], "Remote session active: Jane Doe (Example IT)") {
		t.Fatalf("consent / indicator: questions=%d indicators=%v", len(questions), indicators)
	}

	// Signed inputs 1..3 reach the shell.
	e.sendInput(sessionID, 1, "echo dz-$((6*7))\n")
	e.expectOutput(sessionID, `dz-42`)
	now := time.Now().UTC()
	if _, err := e.srv.SendSigned(e.device, protocol.TypeSessionInput, protocol.SessionInput{
		DeviceID: e.device, SessionID: sessionID, Seq: 2, Kind: protocol.SessionInputResize, Cols: 90, Rows: 20,
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	e.sendInput(sessionID, 3, "echo size=$(stty size | tr ' ' x)=\n")
	e.expectOutput(sessionID, `size=20x90=`)

	// A replayed sequence number is refused ...
	mark = e.srv.Mark(e.device)
	ref := e.sendInput(sessionID, 3, "echo replay-$((100+1))\n")
	if p := e.awaitError(mark, ref); p.Code != protocol.ErrCodeReplayed {
		t.Errorf("replayed seq: code = %q", p.Code)
	}
	// ... as is one that skips ahead ...
	ref = e.sendInput(sessionID, 9, "echo skip-$((200+2))\n")
	if p := e.awaitError(mark, ref); p.Code != protocol.ErrCodeReplayed {
		t.Errorf("out-of-order seq: code = %q", p.Code)
	}
	// ... an unsigned input ...
	unsigned, err := protocol.NewEnvelope(protocol.TypeSessionInput, e.inputPayload(sessionID, 4, "echo unsigned-$((300+3))\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Send(e.device, unsigned); err != nil {
		t.Fatal(err)
	}
	if p := e.awaitError(mark, envID(t, unsigned)); p.Code != protocol.ErrCodeUnsigned {
		t.Errorf("unsigned input: code = %q", p.Code)
	}
	// ... one signed by a key the agent does not trust ...
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(e.inputPayload(sessionID, 4, "echo rogue-$((400+4))\n"))
	forged := testserver.SignEnvelope(rogue, e.srv.KeyID, protocol.TypeSessionInput, raw)
	if err := e.srv.Send(e.device, forged); err != nil {
		t.Fatal(err)
	}
	if p := e.awaitError(mark, envID(t, forged)); p.Code != protocol.ErrCodeBadSignature {
		t.Errorf("forged input: code = %q", p.Code)
	}
	// ... and one for another device.
	other := e.inputPayload(sessionID, 4, "echo other-$((500+5))\n")
	other.DeviceID = protocol.NewID()
	ref, err = e.srv.SendSigned(e.device, protocol.TypeSessionInput, other)
	if err != nil {
		t.Fatal(err)
	}
	if p := e.awaitError(mark, ref); p.Code != protocol.ErrCodeWrongDevice {
		t.Errorf("wrong device: code = %q", p.Code)
	}

	// None of the refused inputs moved the sequence: 4 is still next, and
	// none of them reached the shell.
	e.sendInput(sessionID, 4, "echo shellpid=$$= still-$((7*6))-ok\n")
	shellPID := atoi(t, e.expectOutput(sessionID, `shellpid=(\d+)=`))
	e.expectOutput(sessionID, `still-42-ok`)
	out := e.output(sessionID)
	for _, forbidden := range []string{"replay-101", "skip-202", "unsigned-303", "rogue-404", "other-505"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("a refused input was executed: %s", forbidden)
		}
	}

	// session.end ends it; the shell is gone and later input is refused.
	mark = e.srv.Mark(e.device)
	if _, err := e.srv.SendSigned(e.device, protocol.TypeSessionEnd, protocol.SessionEnd{
		SignedCommon: testserver.Common(e.device), SessionID: sessionID, Reason: "done",
	}); err != nil {
		t.Fatal(err)
	}
	if st := e.awaitStatus(mark, sessionID, protocol.SessionEnded); st.Reason != ReasonEndedByServer {
		t.Errorf("reason = %q", st.Reason)
	}
	waitDead(t, "shell", shellPID)
	if _, _, _, stopped := e.ui.Snapshot(); stopped != 1 {
		t.Errorf("indicator stopped %d times", stopped)
	}
	ref = e.sendInput(sessionID, 5, "echo late-$((600+6))\n")
	if p := e.awaitError(mark, ref); p.Code != protocol.ErrCodeMalformed {
		t.Errorf("input after the end: code = %q (%s)", p.Code, p.Message)
	}
}

func TestEndToEndSessionDiesWithTheConnection(t *testing.T) {
	e := startE2E(t)
	sessionID := protocol.NewID()
	mark := e.srv.Mark(e.device)
	if _, err := e.srv.SendSigned(e.device, protocol.TypeSessionStart, protocol.SessionStart{
		SignedCommon: testserver.Common(e.device),
		SessionID:    sessionID, Kind: protocol.SessionKindTerminal, Consent: protocol.ConsentNone,
		RequestedBy: "Jane Doe (Example IT)",
		Terminal:    &protocol.TerminalOptions{Cols: 80, Rows: 24, RunAs: protocol.RunAsSystem},
	}); err != nil {
		t.Fatal(err)
	}
	e.awaitStatus(mark, sessionID, protocol.SessionActive)
	// Consent mode "none" still shows the indicator.
	if _, questions, indicators, _ := e.ui.Snapshot(); len(questions) != 0 || len(indicators) != 1 {
		t.Fatalf("questions=%d indicators=%d", len(questions), len(indicators))
	}
	e.sendInput(sessionID, 1, "echo shellpid=$$=; sleep 600 & echo bgpid=$!=\n")
	shellPID := atoi(t, e.expectOutput(sessionID, `shellpid=(\d+)=`))
	bgPID := atoi(t, e.expectOutput(sessionID, `bgpid=(\d+)=`))

	// The control connection drops: fail closed.
	e.srv.Disconnect(e.device)
	waitDead(t, "shell", shellPID)
	waitDead(t, "background job", bgPID)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, _, _, stopped := e.ui.Snapshot(); stopped == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the indicator was not removed")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// After the agent reconnects the old session cannot be continued.
	if err := e.srv.AwaitConnections(e.device, 2, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	mark = e.srv.Mark(e.device)
	ref := e.sendInput(sessionID, 2, "echo again\n")
	if p := e.awaitError(mark, ref); p.Code != protocol.ErrCodeMalformed {
		t.Errorf("input for a session of the previous connection: code = %q", p.Code)
	}
}
