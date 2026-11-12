package agentcore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/identity"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
	"github.com/dranzo/dranzormm/agent/internal/transport"
	"github.com/dranzo/dranzormm/agent/internal/trust"
)

const wait = 20 * time.Second

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t      *testing.T
	srv    *testserver.Server
	paths  config.Paths
	logs   *syncBuffer
	agent  *agentcore.Agent
	cancel context.CancelFunc
	done   chan error
	device string

	stopOnce sync.Once
}

func fastBackoff() *transport.Backoff {
	return &transport.Backoff{Base: 20 * time.Millisecond, Cap: 200 * time.Millisecond}
}

// prepare writes the trust anchors and bootstrap.json into a temp data dir,
// like "dranzo-agent install" does.
func prepare(t *testing.T, srv *testserver.Server, serverURL string) config.Paths {
	t.Helper()
	paths := config.ResolvePaths(filepath.Join(t.TempDir(), "data"))
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := trust.Install(paths.CAFile(), paths.TrustFile(), srv.CAPEM, srv.TrustKeys()); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveBootstrap(paths, &config.Bootstrap{ServerURL: serverURL, Token: srv.Token}); err != nil {
		t.Fatal(err)
	}
	return paths
}

func start(t *testing.T, srv *testserver.Server, paths config.Paths, mut func(*agentcore.Options)) *harness {
	t.Helper()
	h := &harness{t: t, srv: srv, paths: paths, logs: &syncBuffer{}, done: make(chan error, 1)}
	opts := agentcore.Options{
		Paths:            paths,
		Logger:           logging.NewWithWriter(h.logs, slog.LevelDebug),
		Platform:         &platform.Fake{ID: "machine-e2e", Users: []string{"tester"}},
		Version:          "9.9.9-test",
		Backoff:          fastBackoff(),
		JobFlushInterval: 20 * time.Millisecond,
		RenewFirstCheck:  time.Hour,
	}
	if mut != nil {
		mut(&opts)
	}
	agent, err := agentcore.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h.agent = agent
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- agent.Run(ctx) }()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case <-h.done:
		case <-time.After(30 * time.Second):
			h.t.Error("agent did not stop")
		}
	})
}

func (h *harness) awaitOnline() {
	h.t.Helper()
	id, err := h.srv.AwaitDevice(wait)
	if err != nil {
		h.t.Fatalf("agent did not enroll: %v\nlogs:\n%s", err, h.logs.String())
	}
	h.device = id
	if err := h.srv.AwaitConnected(id, wait); err != nil {
		h.t.Fatalf("agent did not connect: %v\nlogs:\n%s", err, h.logs.String())
	}
}

func (h *harness) await(from int, msgType string, match func(*protocol.Envelope) bool) *protocol.Envelope {
	h.t.Helper()
	env, err := h.srv.Await(h.device, from, wait, func(e *protocol.Envelope) bool {
		return e.Type == msgType && (match == nil || match(e))
	})
	if err != nil {
		h.t.Fatalf("no %s message: %v\nlogs:\n%s", msgType, err, h.logs.String())
	}
	return env
}

func decode[T any](t *testing.T, env *protocol.Envelope) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(env.Payload, &v); err != nil {
		t.Fatalf("decode %s: %v", env.Type, err)
	}
	return v
}

func (h *harness) awaitResult(from int, jobRunID string) protocol.JobResult {
	h.t.Helper()
	env := h.await(from, protocol.TypeJobResult, func(e *protocol.Envelope) bool {
		return decode[protocol.JobResult](h.t, e).JobRunID == jobRunID
	})
	return decode[protocol.JobResult](h.t, env)
}

func (h *harness) awaitError(from int, refID string) protocol.ErrorPayload {
	h.t.Helper()
	env := h.await(from, protocol.TypeError, func(e *protocol.Envelope) bool {
		return decode[protocol.ErrorPayload](h.t, e).RefID == refID
	})
	return decode[protocol.ErrorPayload](h.t, env)
}

func envelopeID(t *testing.T, data []byte) string {
	t.Helper()
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.ID
}

type dispatchOpts struct {
	body   string
	marker string
	common *protocol.SignedCommon
	kind   string
	spec   any
}

// dispatch builds a job.dispatch payload for the marker script.
func (h *harness) dispatch(o dispatchOpts) protocol.JobDispatch {
	common := testserver.Common(h.device)
	if o.common != nil {
		common = *o.common
	}
	kind := o.kind
	if kind == "" {
		kind = protocol.KindScript
	}
	spec := o.spec
	if spec == nil {
		body := o.body
		if body == "" {
			body = markerScript
		}
		spec = protocol.ScriptSpec{
			Language: scriptLanguage, Body: body, Args: []string{"hello"},
			Env: map[string]string{"MARKER": o.marker}, RunAs: protocol.RunAsSystem,
		}
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		h.t.Fatal(err)
	}
	return protocol.JobDispatch{
		SignedCommon: common, JobRunID: protocol.NewID(), Kind: kind,
		TimeoutSeconds: 60, MaxOutputBytes: 1 << 20, Spec: raw,
	}
}

func markerLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(strings.Fields(string(data)))
}

func TestEndToEnd(t *testing.T) {
	srv, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	paths := prepare(t, srv, srv.URL)
	h := start(t, srv, paths, nil)
	h.awaitOnline()
	markers := t.TempDir()

	t.Run("enrollment", func(t *testing.T) {
		if srv.EnrollCount() != 1 {
			t.Fatalf("enroll count %d", srv.EnrollCount())
		}
		// The token is gone from disk and never reached the log.
		raw, err := os.ReadFile(paths.BootstrapFile())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "dz_enroll_") {
			t.Fatalf("enrollment token still in bootstrap.json: %s", raw)
		}
		secret := strings.TrimPrefix(srv.Token, "dz_enroll_")
		filepath.WalkDir(paths.StateDir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if data, _ := os.ReadFile(p); strings.Contains(string(data), secret) {
					t.Errorf("enrollment token found in %s", p)
				}
			}
			return nil
		})
		if strings.Contains(h.logs.String(), secret) {
			t.Fatal("enrollment token was logged")
		}
		keyPEM, err := os.ReadFile(paths.KeyFile())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(h.logs.String(), strings.Split(string(keyPEM), "\n")[1]) {
			t.Fatal("private key was logged")
		}
		if os.PathSeparator == '/' {
			for _, f := range []string{paths.KeyFile(), paths.CertFile(), paths.ConfigFile(), paths.TrustFile(), paths.CAFile(), paths.NoncesFile()} {
				fi, err := os.Stat(f)
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("%s has mode %v", f, fi.Mode().Perm())
				}
			}
		}
		cfg, err := config.Load(paths)
		if err != nil || cfg.DeviceID != h.device || cfg.ServerURL != srv.URL {
			t.Fatalf("config.json: %+v %v", cfg, err)
		}
	})

	t.Run("hello heartbeat inventory", func(t *testing.T) {
		hello := decode[protocol.Hello](t, h.await(0, protocol.TypeHello, nil))
		if hello.AgentVersion != "9.9.9-test" || hello.ProtocolVersion != 1 || hello.OS != platform.OSFamily || hello.Hostname == "" {
			t.Fatalf("hello: %+v", hello)
		}
		if len(hello.TrustKeyIDs) != 1 || hello.TrustKeyIDs[0] != srv.KeyID {
			t.Fatalf("trustKeyIds: %v", hello.TrustKeyIDs)
		}
		for _, kind := range []string{protocol.KindScript, protocol.KindInventoryRefresh, protocol.KindAgentConfigure, protocol.KindAgentUninstall} {
			if !sort.StringsAreSorted(hello.Capabilities) || !contains(hello.Capabilities, kind) {
				t.Fatalf("capabilities %v lack %s", hello.Capabilities, kind)
			}
		}
		// hello is the very first message of the connection.
		if first := srv.Messages(h.device, 0)[0]; first.Type != protocol.TypeHello {
			t.Fatalf("first message was %s", first.Type)
		}
		hb := decode[protocol.Heartbeat](t, h.await(0, protocol.TypeHeartbeat, nil))
		if hb.Seq != 1 || hb.AgentRSSBytes == 0 || hb.UptimeSeconds == 0 {
			t.Fatalf("heartbeat: %+v", hb)
		}
		inv := decode[protocol.Inventory](t, h.await(0, protocol.TypeInventory, nil))
		if inv.Hostname == "" || inv.MachineID != "machine-e2e" || inv.OS == nil || inv.OS.Family != platform.OSFamily ||
			inv.Agent == nil || inv.Agent.Version != "9.9.9-test" || len(inv.LoggedInUsers) != 1 {
			t.Fatalf("inventory: %+v", inv)
		}
	})

	t.Run("signed script job runs and streams output", func(t *testing.T) {
		marker := filepath.Join(markers, "ok")
		d := h.dispatch(dispatchOpts{marker: marker})
		mark := srv.Mark(h.device)
		if _, err := srv.SendSigned(h.device, protocol.TypeJobDispatch, d); err != nil {
			t.Fatal(err)
		}
		res := h.awaitResult(mark, d.JobRunID)
		if res.Status != protocol.StatusFailed || res.ExitCode == nil || *res.ExitCode != 3 {
			t.Fatalf("result: %+v", res)
		}
		if markerLines(t, marker) != 1 {
			t.Fatal("script did not run exactly once")
		}
		// ack first, then output chunks with increasing seq, then exactly one result.
		var ack *protocol.JobAck
		var stdout, stderr, all strings.Builder
		var lastSeq uint64
		results := 0
		for _, env := range srv.Messages(h.device, mark) {
			switch env.Type {
			case protocol.TypeJobAck:
				a := decode[protocol.JobAck](t, env)
				if a.JobRunID == d.JobRunID {
					if all.Len() > 0 || results > 0 {
						t.Fatal("job.ack arrived after output")
					}
					ack = &a
				}
			case protocol.TypeJobOutput:
				o := decode[protocol.JobOutput](t, env)
				if o.JobRunID != d.JobRunID {
					continue
				}
				if ack == nil {
					t.Fatal("output before ack")
				}
				if o.Seq != lastSeq+1 {
					t.Fatalf("seq %d after %d", o.Seq, lastSeq)
				}
				lastSeq = o.Seq
				all.WriteString(o.Data)
				if o.Stream == protocol.StreamStdout {
					stdout.WriteString(o.Data)
				} else {
					stderr.WriteString(o.Data)
				}
			case protocol.TypeJobResult:
				if decode[protocol.JobResult](t, env).JobRunID == d.JobRunID {
					results++
				}
			}
		}
		if ack == nil || !ack.Accepted {
			t.Fatalf("ack: %+v", ack)
		}
		if results != 1 {
			t.Fatalf("%d results", results)
		}
		if !strings.Contains(stdout.String(), "out:hello") || !strings.Contains(stderr.String(), "err-line") {
			t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
		}
		sum := sha256.Sum256([]byte(all.String()))
		if res.OutputSHA256 != hex.EncodeToString(sum[:]) || res.OutputBytes != int64(all.Len()) || res.Truncated {
			t.Fatalf("output accounting wrong: %+v (delivered %d bytes)", res, all.Len())
		}
		if res.StartedAt.IsZero() || res.FinishedAt.Before(res.StartedAt) {
			t.Fatalf("timestamps: %+v", res)
		}
		// The script body is not in the log; its hash is.
		logs := h.logs.String()
		bodySum := sha256.Sum256([]byte(markerScript))
		if !strings.Contains(logs, hex.EncodeToString(bodySum[:])) || strings.Contains(logs, "err-line") {
			t.Fatal("log must contain the script hash and not the script body")
		}
	})

	// Every refusal: the documented error code, refId = envelope id, and no execution.
	refused := []struct {
		name string
		code string
		// ack tells whether a negative job.ack is expected (signature verified).
		ack   bool
		build func(marker string) (data []byte, jobRunID string)
	}{
		{"unsigned", protocol.ErrCodeUnsigned, false, func(marker string) ([]byte, string) {
			d := h.dispatch(dispatchOpts{marker: marker})
			raw, _ := json.Marshal(d)
			data, _ := json.Marshal(protocol.Envelope{Type: protocol.TypeJobDispatch, ID: protocol.NewID(), Version: 1, Payload: raw})
			return data, d.JobRunID
		}},
		{"bad signature (tampered payload)", protocol.ErrCodeBadSignature, false, func(marker string) ([]byte, string) {
			// Sign a harmless payload, then swap in a different one.
			good := h.dispatch(dispatchOpts{marker: filepath.Join(markers, "never"), body: "exit 0\n"})
			evil := h.dispatch(dispatchOpts{marker: marker})
			var env protocol.Envelope
			_ = json.Unmarshal(srv.Sign(protocol.TypeJobDispatch, good), &env)
			raw, _ := json.Marshal(evil)
			sp := base64.StdEncoding.EncodeToString(raw)
			env.SignedPayload = &sp
			data, _ := json.Marshal(env)
			return data, evil.JobRunID
		}},
		{"bad signature (trusted kid, wrong key)", protocol.ErrCodeBadSignature, false, func(marker string) ([]byte, string) {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			d := h.dispatch(dispatchOpts{marker: marker})
			raw, _ := json.Marshal(d)
			return testserver.SignEnvelope(priv, srv.KeyID, protocol.TypeJobDispatch, raw), d.JobRunID
		}},
		{"unknown key", protocol.ErrCodeUnknownKey, false, func(marker string) ([]byte, string) {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			d := h.dispatch(dispatchOpts{marker: marker})
			raw, _ := json.Marshal(d)
			return testserver.SignEnvelope(priv, "attacker-key", protocol.TypeJobDispatch, raw), d.JobRunID
		}},
		{"expired", protocol.ErrCodeExpired, true, func(marker string) ([]byte, string) {
			c := testserver.Common(h.device)
			c.IssuedAt = time.Now().UTC().Add(-10 * time.Minute)
			c.ExpiresAt = time.Now().UTC().Add(-5 * time.Minute)
			d := h.dispatch(dispatchOpts{marker: marker, common: &c})
			return srv.Sign(protocol.TypeJobDispatch, d), d.JobRunID
		}},
		{"not yet valid", protocol.ErrCodeNotYetValid, true, func(marker string) ([]byte, string) {
			c := testserver.Common(h.device)
			c.IssuedAt = time.Now().UTC().Add(30 * time.Minute)
			c.ExpiresAt = time.Now().UTC().Add(35 * time.Minute)
			d := h.dispatch(dispatchOpts{marker: marker, common: &c})
			return srv.Sign(protocol.TypeJobDispatch, d), d.JobRunID
		}},
		{"validity too long", protocol.ErrCodeValidityTooLong, true, func(marker string) ([]byte, string) {
			c := testserver.Common(h.device)
			c.ExpiresAt = c.IssuedAt.Add(24 * time.Hour)
			d := h.dispatch(dispatchOpts{marker: marker, common: &c})
			return srv.Sign(protocol.TypeJobDispatch, d), d.JobRunID
		}},
		{"wrong device", protocol.ErrCodeWrongDevice, true, func(marker string) ([]byte, string) {
			c := testserver.Common(protocol.NewID())
			d := h.dispatch(dispatchOpts{marker: marker, common: &c})
			return srv.Sign(protocol.TypeJobDispatch, d), d.JobRunID
		}},
	}
	for i, c := range refused {
		t.Run("refuses "+c.name, func(t *testing.T) {
			marker := filepath.Join(markers, "refused-"+string(rune('a'+i)))
			data, jobRunID := c.build(marker)
			mark := srv.Mark(h.device)
			if err := srv.Send(h.device, data); err != nil {
				t.Fatal(err)
			}
			e := h.awaitError(mark, envelopeID(t, data))
			if e.Code != c.code {
				t.Fatalf("error code %q, want %q (%s)", e.Code, c.code, e.Message)
			}
			// A following valid command proves the agent finished handling the
			// refused one; by then anything it started would have left traces.
			probe := h.dispatch(dispatchOpts{kind: protocol.KindInventoryRefresh, spec: struct{}{}})
			if _, err := srv.SendSigned(h.device, protocol.TypeJobDispatch, probe); err != nil {
				t.Fatal(err)
			}
			h.awaitResult(mark, probe.JobRunID)
			time.Sleep(150 * time.Millisecond)

			if markerLines(t, marker) != 0 {
				t.Fatal("a refused command was executed")
			}
			var negAck bool
			for _, env := range srv.Messages(h.device, mark) {
				switch env.Type {
				case protocol.TypeJobAck:
					a := decode[protocol.JobAck](t, env)
					if a.JobRunID != jobRunID {
						continue
					}
					if a.Accepted {
						t.Fatal("refused job was acknowledged as accepted")
					}
					if a.Reason != c.code {
						t.Fatalf("negative ack reason %q", a.Reason)
					}
					negAck = true
				case protocol.TypeJobOutput:
					if decode[protocol.JobOutput](t, env).JobRunID == jobRunID {
						t.Fatal("refused job produced output")
					}
				case protocol.TypeJobResult:
					if decode[protocol.JobResult](t, env).JobRunID == jobRunID {
						t.Fatal("refused job produced a result")
					}
				}
			}
			if negAck != c.ack {
				t.Fatalf("negative job.ack sent=%v, want %v", negAck, c.ack)
			}
		})
	}

	t.Run("refuses replayed", func(t *testing.T) {
		marker := filepath.Join(markers, "replay")
		d := h.dispatch(dispatchOpts{marker: marker})
		data := srv.Sign(protocol.TypeJobDispatch, d)
		mark := srv.Mark(h.device)
		if err := srv.Send(h.device, data); err != nil {
			t.Fatal(err)
		}
		h.awaitResult(mark, d.JobRunID)
		if markerLines(t, marker) != 1 {
			t.Fatal("first delivery did not run")
		}
		// The identical signed envelope again.
		mark = srv.Mark(h.device)
		if err := srv.Send(h.device, data); err != nil {
			t.Fatal(err)
		}
		if e := h.awaitError(mark, envelopeID(t, data)); e.Code != protocol.ErrCodeReplayed {
			t.Fatalf("error code %q", e.Code)
		}
		probe := h.dispatch(dispatchOpts{kind: protocol.KindInventoryRefresh, spec: struct{}{}})
		_, _ = srv.SendSigned(h.device, protocol.TypeJobDispatch, probe)
		h.awaitResult(mark, probe.JobRunID)
		time.Sleep(150 * time.Millisecond)
		if n := markerLines(t, marker); n != 1 {
			t.Fatalf("replayed command was executed (marker has %d lines)", n)
		}
		for _, env := range srv.Messages(h.device, mark) {
			if env.Type == protocol.TypeJobResult && decode[protocol.JobResult](t, env).JobRunID == d.JobRunID {
				t.Fatal("replayed job produced a second result")
			}
		}
	})

	t.Run("unsigned control messages are refused", func(t *testing.T) {
		for _, typ := range []string{protocol.TypeJobCancel, protocol.TypeUpdateAvailable, protocol.TypeSessionStart,
			protocol.TypeSessionInput, protocol.TypeSessionEnd, protocol.TypeTrustRotate} {
			data, _ := json.Marshal(protocol.Envelope{Type: typ, ID: protocol.NewID(), Version: 1,
				Payload: json.RawMessage(`{"deviceId":"` + h.device + `","commandKeys":[]}`)})
			mark := srv.Mark(h.device)
			if err := srv.Send(h.device, data); err != nil {
				t.Fatal(err)
			}
			if e := h.awaitError(mark, envelopeID(t, data)); e.Code != protocol.ErrCodeUnsigned {
				t.Fatalf("%s: code %q", typ, e.Code)
			}
		}
		// The trust store is untouched.
		store, err := trust.Load(paths.CAFile(), paths.TrustFile())
		if err != nil || len(store.KeyIDs()) != 1 || store.KeyIDs()[0] != srv.KeyID {
			t.Fatalf("trust store changed: %v %v", store, err)
		}
	})

	t.Run("unknown type and bad version", func(t *testing.T) {
		data, _ := json.Marshal(protocol.Envelope{Type: "does.not.exist", ID: protocol.NewID(), Version: 1})
		mark := srv.Mark(h.device)
		_ = srv.Send(h.device, data)
		if e := h.awaitError(mark, envelopeID(t, data)); e.Code != protocol.ErrCodeUnknownType {
			t.Fatalf("code %q", e.Code)
		}
		// Garbage does not kill the connection.
		mark = srv.Mark(h.device)
		_ = srv.Send(h.device, []byte(`{not json`))
		if e := decode[protocol.ErrorPayload](t, h.await(mark, protocol.TypeError, nil)); e.Code != protocol.ErrCodeMalformed {
			t.Fatalf("code %q", e.Code)
		}
	})

	t.Run("cancel kills a running job", func(t *testing.T) {
		d := h.dispatch(dispatchOpts{body: sleepScript, marker: filepath.Join(markers, "unused")})
		mark := srv.Mark(h.device)
		if _, err := srv.SendSigned(h.device, protocol.TypeJobDispatch, d); err != nil {
			t.Fatal(err)
		}
		h.await(mark, protocol.TypeJobAck, func(e *protocol.Envelope) bool { return decode[protocol.JobAck](t, e).JobRunID == d.JobRunID })
		time.Sleep(300 * time.Millisecond)
		started := time.Now()
		if _, err := srv.SendSigned(h.device, protocol.TypeJobCancel, protocol.JobCancel{SignedCommon: testserver.Common(h.device), JobRunID: d.JobRunID}); err != nil {
			t.Fatal(err)
		}
		res := h.awaitResult(mark, d.JobRunID)
		if res.Status != protocol.StatusCancelled {
			t.Fatalf("result %+v", res)
		}
		if time.Since(started) > 15*time.Second {
			t.Fatal("cancel was slow")
		}
	})

	t.Run("unknown job kind is unsupported", func(t *testing.T) {
		d := h.dispatch(dispatchOpts{kind: "future.kind", spec: struct{}{}})
		mark := srv.Mark(h.device)
		_, _ = srv.SendSigned(h.device, protocol.TypeJobDispatch, d)
		if res := h.awaitResult(mark, d.JobRunID); res.Status != protocol.StatusUnsupported {
			t.Fatalf("%+v", res)
		}
	})

	t.Run("inventory.refresh sends a fresh inventory", func(t *testing.T) {
		d := h.dispatch(dispatchOpts{kind: protocol.KindInventoryRefresh, spec: struct{}{}})
		mark := srv.Mark(h.device)
		_, _ = srv.SendSigned(h.device, protocol.TypeJobDispatch, d)
		if res := h.awaitResult(mark, d.JobRunID); res.Status != protocol.StatusSucceeded {
			t.Fatalf("%+v", res)
		}
		h.await(mark, protocol.TypeInventory, nil)
	})

	t.Run("agent.configure sets and clears the uninstall code", func(t *testing.T) {
		salt := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
		hash := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		send := func(spec string) protocol.JobResult {
			d := h.dispatch(dispatchOpts{kind: protocol.KindAgentConfigure, spec: json.RawMessage(spec)})
			mark := srv.Mark(h.device)
			_, _ = srv.SendSigned(h.device, protocol.TypeJobDispatch, d)
			return h.awaitResult(mark, d.JobRunID)
		}
		if res := send(`{"uninstallCode":{"salt":"` + salt + `","iterations":600000,"hash":"` + hash + `"}}`); res.Status != protocol.StatusSucceeded {
			t.Fatalf("%+v", res)
		}
		if cfg, _ := config.Load(paths); cfg.UninstallCode == nil || cfg.UninstallCode.Iterations != 600000 {
			t.Fatalf("uninstall code not stored: %+v", cfg)
		}
		// Weak parameters are rejected and leave the stored code alone.
		if res := send(`{"uninstallCode":{"salt":"` + salt + `","iterations":10,"hash":"` + hash + `"}}`); res.Status != protocol.StatusRejected {
			t.Fatalf("%+v", res)
		}
		// An absent key changes nothing; null clears.
		if res := send(`{}`); res.Status != protocol.StatusSucceeded {
			t.Fatalf("%+v", res)
		}
		if cfg, _ := config.Load(paths); cfg.UninstallCode == nil {
			t.Fatal("uninstall code lost")
		}
		if res := send(`{"uninstallCode":null}`); res.Status != protocol.StatusSucceeded {
			t.Fatalf("%+v", res)
		}
		if cfg, _ := config.Load(paths); cfg.UninstallCode != nil {
			t.Fatal("uninstall code not cleared")
		}
	})

	t.Run("sessions and updates answer not supported in this build", func(t *testing.T) {
		sid := protocol.NewID()
		mark := srv.Mark(h.device)
		_, _ = srv.SendSigned(h.device, protocol.TypeSessionStart, protocol.SessionStart{
			SignedCommon: testserver.Common(h.device), SessionID: sid, Kind: protocol.SessionKindTerminal,
			Consent: protocol.ConsentRequire, ConsentTimeoutSeconds: 60, RequestedBy: "Jane Doe (Example IT)",
			Terminal: &protocol.TerminalOptions{Cols: 120, Rows: 30, RunAs: protocol.RunAsSystem},
		})
		st := decode[protocol.SessionStatus](t, h.await(mark, protocol.TypeSessionStatus, nil))
		if st.SessionID != sid || st.State != protocol.SessionFailed || !strings.Contains(st.Reason, "not supported") {
			t.Fatalf("%+v", st)
		}
		// Input for a session that never became active is refused.
		now := time.Now().UTC()
		id, _ := srv.SendSigned(h.device, protocol.TypeSessionInput, protocol.SessionInput{
			DeviceID: h.device, SessionID: sid, Seq: 1, Kind: protocol.SessionInputData, Data: "bHMK",
			IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		})
		if e := h.awaitError(mark, id); e.Code != protocol.ErrCodeMalformed {
			t.Fatalf("session.input: %+v", e)
		}
		blob, sum := srv.AddBlob([]byte("new-agent-binary"))
		mark = srv.Mark(h.device)
		_, _ = srv.SendSigned(h.device, protocol.TypeUpdateAvailable, protocol.UpdateAvailable{
			SignedCommon: testserver.Common(h.device), Version: "10.0.0", BlobID: blob, SHA256: sum, SizeBytes: 16, Ring: "pilot",
		})
		us := decode[protocol.UpdateStatus](t, h.await(mark, protocol.TypeUpdateStatus, nil))
		if us.Version != "10.0.0" || us.State != protocol.UpdateFailed {
			t.Fatalf("%+v", us)
		}
	})

	t.Run("replay is refused after a restart", func(t *testing.T) {
		marker := filepath.Join(markers, "replay-restart")
		d := h.dispatch(dispatchOpts{marker: marker})
		data := srv.Sign(protocol.TypeJobDispatch, d)
		mark := srv.Mark(h.device)
		_ = srv.Send(h.device, data)
		h.awaitResult(mark, d.JobRunID)

		// Stop the agent and start a new one on the same data directory.
		h.stop()
		connsBefore := len(srv.ConnThumbprints(h.device))
		h2 := start(t, srv, paths, nil)
		h2.device = h.device
		if err := srv.AwaitConnections(h.device, connsBefore+1, wait); err != nil {
			t.Fatalf("agent did not reconnect after restart: %v\n%s", err, h2.logs.String())
		}
		if srv.EnrollCount() != 1 {
			t.Fatal("agent enrolled again after restart")
		}
		mark = srv.Mark(h.device)
		h2.await(mark-1, protocol.TypeHello, nil)
		if err := srv.Send(h.device, data); err != nil {
			t.Fatal(err)
		}
		if e := h2.awaitError(mark, envelopeID(t, data)); e.Code != protocol.ErrCodeReplayed {
			t.Fatalf("code %q", e.Code)
		}
		time.Sleep(200 * time.Millisecond)
		if n := markerLines(t, marker); n != 1 {
			t.Fatalf("command replayed after restart was executed (%d runs)", n)
		}
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestCertificateRenewalSwitch(t *testing.T) {
	srv, err := testserver.New(testserver.Options{BackdateFirstCert: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	paths := prepare(t, srv, srv.URL)
	h := start(t, srv, paths, func(o *agentcore.Options) {
		o.RenewFirstCheck = 300 * time.Millisecond
		o.RenewCheckInterval = 300 * time.Millisecond
	})
	h.awaitOnline()
	first := srv.ConnThumbprints(h.device)[0]

	// The agent notices that less than a third of the lifetime remains, renews
	// over mTLS and reconnects with the new certificate.
	if err := srv.AwaitCond(wait, func() bool { return srv.RenewCountLocked() == 1 }); err != nil {
		t.Fatalf("no renewal: %v\n%s", err, h.logs.String())
	}
	var current string
	if err := srv.AwaitCond(wait, func() bool {
		tps := srv.ConnThumbprintsLocked(h.device)
		current = srv.CurrentThumbprintLocked(h.device)
		return len(tps) >= 2 && tps[len(tps)-1] == current
	}); err != nil {
		t.Fatalf("agent did not reconnect with the renewed certificate: %v\n%s", err, h.logs.String())
	}
	if current == first {
		t.Fatal("certificate did not change")
	}
	// The server retired the old certificate on first use of the new one.
	if _, prev := srv.Thumbprints(h.device); prev != "" {
		t.Fatal("previous certificate still accepted")
	}
	// On disk: the new pair, complete, no leftovers from the switch.
	id, err := identity.NewStore(paths.KeyFile(), paths.CertFile()).Load()
	if err != nil {
		t.Fatal(err)
	}
	if id.Thumbprint() != current || id.DeviceID != h.device {
		t.Fatal("device.crt on disk is not the renewed certificate")
	}
	for _, leftover := range []string{paths.KeyFile() + ".next", paths.CertFile() + ".next"} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", leftover)
		}
	}
	// It renews once, not on every check, and the device id is unchanged.
	time.Sleep(time.Second)
	if srv.RenewCount() != 1 || srv.EnrollCount() != 1 {
		t.Fatalf("renewals=%d enrollments=%d", srv.RenewCount(), srv.EnrollCount())
	}
	// The connection with the new certificate works: a signed job still runs.
	if err := srv.AwaitConnected(h.device, wait); err != nil {
		t.Fatal(err)
	}
	d := h.dispatch(dispatchOpts{kind: protocol.KindInventoryRefresh, spec: struct{}{}})
	mark := srv.Mark(h.device)
	if _, err := srv.SendSigned(h.device, protocol.TypeJobDispatch, d); err != nil {
		t.Fatal(err)
	}
	if res := h.awaitResult(mark, d.JobRunID); res.Status != protocol.StatusSucceeded {
		t.Fatalf("%+v", res)
	}
}

func TestRefusesServerNotFromPinnedCA(t *testing.T) {
	trusted, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer trusted.Close()
	impostor, err := testserver.New(testserver.Options{Token: trusted.Token}) // different CA, same token
	if err != nil {
		t.Fatal(err)
	}
	defer impostor.Close()

	// The agent pins the trusted CA but is pointed at the impostor.
	paths := prepare(t, trusted, impostor.URL)
	h := start(t, trusted, paths, nil)

	// Give it time for several attempts (the test backoff is 20-200 ms).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && strings.Count(h.logs.String(), "enrollment failed") < 3 {
		time.Sleep(50 * time.Millisecond)
	}
	logs := h.logs.String()
	if strings.Count(logs, "enrollment failed") < 3 {
		t.Fatalf("expected repeated enrollment failures, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "unknown authority") && !strings.Contains(logs, "certificate") {
		t.Fatalf("expected a certificate verification error, logs:\n%s", logs)
	}
	if impostor.Hits("enroll") != 0 || impostor.EnrollCount() != 0 || len(impostor.Devices()) != 0 {
		t.Fatal("the agent sent its enrollment token to a server that is not from the pinned CA")
	}
	if _, err := os.Stat(paths.KeyFile()); !os.IsNotExist(err) {
		t.Fatal("an identity was stored although enrollment never succeeded")
	}
	// The token is still there for the real server, and was never logged.
	b, err := config.LoadBootstrap(paths)
	if err != nil || b.Token != trusted.Token {
		t.Fatalf("bootstrap: %+v %v", b, err)
	}
	if strings.Contains(logs, strings.TrimPrefix(trusted.Token, "dz_enroll_")) {
		t.Fatal("token logged")
	}
}

func TestRefusesToConnectAfterServerCAChanges(t *testing.T) {
	// Enroll against the real server, then point the enrolled agent at an
	// impostor with a different CA: the WebSocket must never be established.
	srv, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	paths := prepare(t, srv, srv.URL)
	h := start(t, srv, paths, nil)
	h.awaitOnline()
	h.stop()

	impostor, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer impostor.Close()
	cfg, err := config.Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerURL = impostor.URL
	if err := config.Save(paths, cfg); err != nil {
		t.Fatal(err)
	}
	h2 := start(t, srv, paths, nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && strings.Count(h2.logs.String(), "connect failed") < 3 {
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Count(h2.logs.String(), "connect failed") < 3 {
		t.Fatalf("expected repeated connect failures, logs:\n%s", h2.logs.String())
	}
	if impostor.Hits("ws") != 0 {
		t.Fatal("the agent talked to a server that is not from the pinned CA")
	}
	if st, err := config.LoadStatus(paths); err != nil || st.Connected {
		t.Fatalf("status file: %+v %v", st, err)
	}
}

func TestTrustRotate(t *testing.T) {
	srv, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	paths := prepare(t, srv, srv.URL)
	h := start(t, srv, paths, nil)
	h.awaitOnline()

	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newKey := protocol.CommandKey{Kid: "rotated-2", Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(newPub)}
	rotate := func(keys []protocol.CommandKey) protocol.TrustRotate {
		return protocol.TrustRotate{SignedCommon: testserver.Common(h.device), CommandKeys: keys}
	}

	// A rotation signed by a key that is NOT in the current trust.json is refused.
	raw, _ := json.Marshal(rotate([]protocol.CommandKey{newKey}))
	forged := testserver.SignEnvelope(newPriv, "rotated-2", protocol.TypeTrustRotate, raw)
	mark := srv.Mark(h.device)
	_ = srv.Send(h.device, forged)
	if e := h.awaitError(mark, envelopeID(t, forged)); e.Code != protocol.ErrCodeUnknownKey {
		t.Fatalf("forged rotation: %+v", e)
	}
	// A correctly signed rotation with invalid content is refused as well.
	mark = srv.Mark(h.device)
	id, _ := srv.SendSigned(h.device, protocol.TypeTrustRotate, rotate(nil))
	if e := h.awaitError(mark, id); e.Code != protocol.ErrCodeMalformed {
		t.Fatalf("empty rotation: %+v", e)
	}
	if store, _ := trust.Load(paths.CAFile(), paths.TrustFile()); len(store.KeyIDs()) != 1 || store.KeyIDs()[0] != srv.KeyID {
		t.Fatal("trust store changed by a refused rotation")
	}

	// The real rotation, signed by the current key.
	conns := len(srv.ConnThumbprints(h.device))
	if _, err := srv.SendSigned(h.device, protocol.TypeTrustRotate, rotate([]protocol.CommandKey{newKey})); err != nil {
		t.Fatal(err)
	}
	// The agent reconnects and announces the new key ids in hello.
	if err := srv.AwaitConnections(h.device, conns+1, wait); err != nil {
		t.Fatalf("no reconnect after rotation: %v\n%s", err, h.logs.String())
	}
	if ids := srv.Hello(h.device).TrustKeyIDs; len(ids) != 1 || ids[0] != "rotated-2" {
		t.Fatalf("hello.trustKeyIds after rotation: %v", ids)
	}
	if store, _ := trust.Load(paths.CAFile(), paths.TrustFile()); len(store.KeyIDs()) != 1 || store.KeyIDs()[0] != "rotated-2" {
		t.Fatal("rotation not persisted")
	}

	// The old key no longer works; the new one does.
	d := h.dispatch(dispatchOpts{kind: protocol.KindInventoryRefresh, spec: struct{}{}})
	mark = srv.Mark(h.device)
	id, _ = srv.SendSigned(h.device, protocol.TypeJobDispatch, d)
	if e := h.awaitError(mark, id); e.Code != protocol.ErrCodeUnknownKey {
		t.Fatalf("old key after rotation: %+v", e)
	}
	d = h.dispatch(dispatchOpts{kind: protocol.KindInventoryRefresh, spec: struct{}{}})
	raw, _ = json.Marshal(d)
	mark = srv.Mark(h.device)
	if err := srv.Send(h.device, testserver.SignEnvelope(newPriv, "rotated-2", protocol.TypeJobDispatch, raw)); err != nil {
		t.Fatal(err)
	}
	if res := h.awaitResult(mark, d.JobRunID); res.Status != protocol.StatusSucceeded {
		t.Fatalf("new key: %+v", res)
	}
}

func TestReconnectsAndResumesAfterServerDrop(t *testing.T) {
	srv, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	paths := prepare(t, srv, srv.URL)
	h := start(t, srv, paths, nil)
	h.awaitOnline()
	h.await(0, protocol.TypeInventory, nil)

	srv.Disconnect(h.device)
	if err := srv.AwaitConnections(h.device, 2, wait); err != nil {
		t.Fatalf("no reconnect: %v\n%s", err, h.logs.String())
	}
	// Each connection starts with hello; heartbeat seq keeps counting.
	mark := srv.Mark(h.device)
	hb := decode[protocol.Heartbeat](t, h.await(mark-1, protocol.TypeHeartbeat, nil))
	if hb.Seq < 2 {
		t.Fatalf("heartbeat seq %d after reconnect", hb.Seq)
	}
	if st, err := config.LoadStatus(paths); err != nil || !st.Connected {
		t.Fatalf("status file: %+v %v", st, err)
	}
}

func TestUnsupportedProtocolVersionClosesConnection(t *testing.T) {
	srv, err := testserver.New(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	paths := prepare(t, srv, srv.URL)
	h := start(t, srv, paths, nil)
	h.awaitOnline()

	// A higher protocol version: error unsupported_version, then the agent closes.
	marker := filepath.Join(t.TempDir(), "v2")
	d := h.dispatch(dispatchOpts{marker: marker})
	var env protocol.Envelope
	_ = json.Unmarshal(srv.Sign(protocol.TypeJobDispatch, d), &env)
	env.Version = 2
	data, _ := json.Marshal(env)
	mark := srv.Mark(h.device)
	if err := srv.Send(h.device, data); err != nil {
		t.Fatal(err)
	}
	if e := h.awaitError(mark, env.ID); e.Code != protocol.ErrCodeUnsupportedVersion {
		t.Fatalf("code %q", e.Code)
	}
	if err := srv.AwaitConnections(h.device, 2, wait); err != nil {
		t.Fatalf("agent did not close and reconnect: %v", err)
	}
	if markerLines(t, marker) != 0 {
		t.Fatal("a command in an unsupported protocol version was executed")
	}
}
