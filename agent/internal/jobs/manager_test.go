package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

type msg struct {
	typ     string
	payload any
}

type recorder struct {
	mu   sync.Mutex
	msgs []msg
	ch   chan struct{}
}

func newRecorder() *recorder { return &recorder{ch: make(chan struct{}, 1024)} }

func (r *recorder) Send(_ context.Context, typ string, payload any) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, msg{typ, payload})
	r.mu.Unlock()
	select {
	case r.ch <- struct{}{}:
	default:
	}
	return nil
}

func (r *recorder) snapshot() []msg {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]msg(nil), r.msgs...)
}

func (r *recorder) result(t *testing.T, id string) protocol.JobResult {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		for _, m := range r.snapshot() {
			if res, ok := m.payload.(protocol.JobResult); ok && res.JobRunID == id {
				return res
			}
		}
		select {
		case <-r.ch:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("no job.result for %s", id)
		}
	}
}

func (r *recorder) acks(id string) []protocol.JobAck {
	var out []protocol.JobAck
	for _, m := range r.snapshot() {
		if a, ok := m.payload.(protocol.JobAck); ok && a.JobRunID == id {
			out = append(out, a)
		}
	}
	return out
}

func jobID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func dispatch(kind string, n int) protocol.JobDispatch {
	return protocol.JobDispatch{JobRunID: jobID(n), Kind: kind, TimeoutSeconds: 30, Spec: json.RawMessage(`{}`)}
}

func TestManagerRunsHandlerAndStreamsOutput(t *testing.T) {
	rec := newRecorder()
	m := NewManager(context.Background(), Options{Sender: rec, DeviceID: "dev", FlushInterval: 10 * time.Millisecond})
	defer m.Shutdown(time.Second)
	m.Register("echo", HandlerFunc(func(jc *JobContext) Result {
		if jc.JobRunID != jobID(1) || jc.DeviceID != "dev" || jc.Kind != "echo" || jc.TimeoutSeconds != 30 {
			return Failed("bad context: %+v", jc)
		}
		fmt.Fprint(jc.Stdout, "hello ")
		fmt.Fprint(jc.Stderr, "warn")
		return SucceededWith(protocol.InstallResult{Installed: true, Version: "1.0"})
	}))
	if err := m.Dispatch(context.Background(), dispatch("echo", 1)); err != nil {
		t.Fatal(err)
	}
	res := rec.result(t, jobID(1))
	if res.Status != protocol.StatusSucceeded || res.OutputBytes != 10 || res.Truncated {
		t.Fatalf("unexpected result %+v", res)
	}
	if r, ok := res.Result.(protocol.InstallResult); !ok || !r.Installed {
		t.Fatalf("result object missing: %+v", res.Result)
	}
	// Order: ack, outputs, result; exactly one ack and one result.
	msgs := rec.snapshot()
	if msgs[0].typ != protocol.TypeJobAck || msgs[len(msgs)-1].typ != protocol.TypeJobResult {
		t.Fatalf("wrong order: %+v", msgs)
	}
	if a := rec.acks(jobID(1)); len(a) != 1 || !a[0].Accepted {
		t.Fatalf("acks: %+v", a)
	}
	var data string
	for _, mm := range msgs {
		if o, ok := mm.payload.(protocol.JobOutput); ok {
			data += o.Data
		}
	}
	if data != "hello warn" {
		t.Fatalf("output %q", data)
	}
}

func TestManagerUnknownKindIsUnsupported(t *testing.T) {
	rec := newRecorder()
	m := NewManager(context.Background(), Options{Sender: rec})
	defer m.Shutdown(time.Second)
	if err := m.Dispatch(context.Background(), dispatch("does.not.exist", 1)); err != nil {
		t.Fatal(err)
	}
	res := rec.result(t, jobID(1))
	if res.Status != protocol.StatusUnsupported || res.OutputSHA256 != emptySHA256 {
		t.Fatalf("%+v", res)
	}
	if a := rec.acks(jobID(1)); len(a) != 1 || !a[0].Accepted {
		t.Fatalf("acks: %+v", a)
	}
}

func TestManagerValidatesDispatch(t *testing.T) {
	rec := newRecorder()
	m := NewManager(context.Background(), Options{Sender: rec})
	defer m.Shutdown(time.Second)
	m.Register("ok", HandlerFunc(func(*JobContext) Result { return Succeeded() }))

	if err := m.Dispatch(context.Background(), protocol.JobDispatch{JobRunID: "nope", Kind: "ok"}); !errors.Is(err, ErrInvalidJobRunID) {
		t.Fatalf("expected ErrInvalidJobRunID, got %v", err)
	}
	bad := "not-a-uuid"
	cases := []protocol.JobDispatch{
		{JobRunID: jobID(1), Kind: "BAD KIND"},
		{JobRunID: jobID(2), Kind: "ok", TimeoutSeconds: -1},
		{JobRunID: jobID(3), Kind: "ok", TimeoutSeconds: protocol.MaxJobTimeoutSeconds + 1},
		{JobRunID: jobID(4), Kind: "ok", MaxOutputBytes: -5},
		{JobRunID: jobID(5), Kind: "ok", SessionID: &bad},
		{JobRunID: jobID(6), Kind: "ok", Spec: json.RawMessage(`[1]`)},
	}
	for _, d := range cases {
		if err := m.Dispatch(context.Background(), d); err != nil {
			t.Fatal(err)
		}
		if res := rec.result(t, d.JobRunID); res.Status != protocol.StatusRejected {
			t.Errorf("%s: expected rejected, got %+v", d.JobRunID, res)
		}
	}
	// Defaults: timeout 0 and maxOutputBytes 0 are accepted.
	if err := m.Dispatch(context.Background(), protocol.JobDispatch{JobRunID: jobID(7), Kind: "ok"}); err != nil {
		t.Fatal(err)
	}
	if res := rec.result(t, jobID(7)); res.Status != protocol.StatusSucceeded {
		t.Fatalf("%+v", res)
	}
}

func TestManagerConcurrencyQueueAndBusy(t *testing.T) {
	rec := newRecorder()
	m := NewManager(context.Background(), Options{Sender: rec, MaxConcurrent: 2, QueueSize: 3})
	defer m.Shutdown(time.Second)
	release := make(chan struct{})
	var mu sync.Mutex
	running, peak := 0, 0
	m.Register("block", HandlerFunc(func(jc *JobContext) Result {
		mu.Lock()
		running++
		if running > peak {
			peak = running
		}
		mu.Unlock()
		select {
		case <-release:
		case <-jc.Ctx.Done():
		}
		mu.Lock()
		running--
		mu.Unlock()
		return Succeeded()
	}))
	// 2 running + 3 queued are accepted; the 6th and 7th are refused as busy.
	for i := 1; i <= 7; i++ {
		if err := m.Dispatch(context.Background(), dispatch("block", i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 5; i++ {
		if a := rec.acks(jobID(i)); len(a) != 1 || !a[0].Accepted {
			t.Fatalf("job %d: %+v", i, a)
		}
	}
	for i := 6; i <= 7; i++ {
		a := rec.acks(jobID(i))
		if len(a) != 1 || a[0].Accepted || a[0].Reason != ReasonBusy {
			t.Fatalf("job %d should be refused as busy: %+v", i, a)
		}
	}
	// A duplicate of a queued job is refused too.
	_ = m.Dispatch(context.Background(), dispatch("block", 4))
	if a := rec.acks(jobID(4)); len(a) != 2 || a[1].Accepted || a[1].Reason != ReasonDuplicate {
		t.Fatalf("duplicate: %+v", a)
	}
	if r, q := m.Active(); r != 2 || q != 3 {
		t.Fatalf("running=%d queued=%d", r, q)
	}
	// Wait until both slots are really inside the handler before releasing.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		mu.Lock()
		n := running
		mu.Unlock()
		if n == 2 {
			break
		}
	}
	close(release)
	for i := 1; i <= 5; i++ {
		if res := rec.result(t, jobID(i)); res.Status != protocol.StatusSucceeded {
			t.Fatalf("job %d: %+v", i, res)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if peak != 2 {
		t.Fatalf("peak concurrency %d, want 2", peak)
	}
	// Refused jobs never produce a result.
	for _, mm := range rec.snapshot() {
		if res, ok := mm.payload.(protocol.JobResult); ok && (res.JobRunID == jobID(6) || res.JobRunID == jobID(7)) {
			t.Fatalf("refused job produced a result: %+v", res)
		}
	}
}

func TestManagerTimeoutAndCancel(t *testing.T) {
	rec := newRecorder()
	m := NewManager(context.Background(), Options{Sender: rec, MaxConcurrent: 1})
	defer m.Shutdown(time.Second)
	m.Register("wait", HandlerFunc(func(jc *JobContext) Result {
		<-jc.Ctx.Done()
		return Failed("killed: %v", jc.Ctx.Err())
	}))

	d := dispatch("wait", 1)
	d.TimeoutSeconds = 1
	_ = m.Dispatch(context.Background(), d)
	if res := rec.result(t, jobID(1)); res.Status != protocol.StatusTimeout {
		t.Fatalf("expected timeout, got %+v", res)
	}

	// Cancel a running job and a queued job.
	_ = m.Dispatch(context.Background(), dispatch("wait", 2))
	_ = m.Dispatch(context.Background(), dispatch("wait", 3))
	if !m.Cancel(jobID(3)) {
		t.Fatal("queued job not found")
	}
	if res := rec.result(t, jobID(3)); res.Status != protocol.StatusCancelled {
		t.Fatalf("queued: %+v", res)
	}
	if !m.Cancel(jobID(2)) {
		t.Fatal("running job not found")
	}
	if res := rec.result(t, jobID(2)); res.Status != protocol.StatusCancelled {
		t.Fatalf("running: %+v", res)
	}
	if m.Cancel(jobID(99)) {
		t.Fatal("unknown job reported as cancelled")
	}
}

func TestManagerHandlerPanicIsContained(t *testing.T) {
	rec := newRecorder()
	m := NewManager(context.Background(), Options{Sender: rec})
	defer m.Shutdown(time.Second)
	m.Register("boom", HandlerFunc(func(*JobContext) Result { panic("boom") }))
	_ = m.Dispatch(context.Background(), dispatch("boom", 1))
	if res := rec.result(t, jobID(1)); res.Status != protocol.StatusFailed {
		t.Fatalf("%+v", res)
	}
}

func TestResultHelpers(t *testing.T) {
	if r := Unsupported("cmd scripts"); r.Status != protocol.StatusUnsupported || r.Message != "not supported on this OS: cmd scripts" {
		t.Fatalf("%+v", r)
	}
	if r := FromExitCode(0); r.Status != protocol.StatusSucceeded || *r.ExitCode != 0 {
		t.Fatalf("%+v", r)
	}
	if r := FromExitCode(3); r.Status != protocol.StatusFailed || *r.ExitCode != 3 {
		t.Fatalf("%+v", r)
	}
}
