package reboot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// fakeRebooter records restart requests; it never restarts anything.
type fakeRebooter struct {
	mu    sync.Mutex
	calls []rebootCall
	err   error
	ch    chan struct{}
}

type rebootCall struct {
	delay   time.Duration
	message string
	at      time.Time
}

func newFakeRebooter() *fakeRebooter { return &fakeRebooter{ch: make(chan struct{}, 16)} }

func (f *fakeRebooter) Reboot(_ context.Context, delay time.Duration, message string) error {
	f.mu.Lock()
	f.calls = append(f.calls, rebootCall{delay: delay, message: message, at: time.Now()})
	err := f.err
	f.mu.Unlock()
	f.ch <- struct{}{}
	return err
}

func (f *fakeRebooter) snapshot() []rebootCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]rebootCall(nil), f.calls...)
}

var alice = &platform.User{Name: "alice", UID: "501"}

func handle(t *testing.T, h *Handler, spec any) (jobs.Result, *swtest.Job) {
	t.Helper()
	job := swtest.NewJob(context.Background(), &platform.Fake{User: alice}, t.TempDir(), spec)
	return h.Handle(job.JobContext), job
}

func TestRebootJobValidation(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	h := NewHandler(ui, rb)
	for _, spec := range []string{
		`{"delaySeconds":-1}`,
		`{"delaySeconds":604801}`,
		`{"delaySeconds":"soon"}`,
		`{"delaySeconds":0,"message":"line\nbreak"}`,
		`{"delaySeconds":0,"message":"bell\u0007"}`,
		`{"delaySeconds":0,"message":"-h now"}`,
		`{"delaySeconds":0,"message":"  --halt"}`,
		`{"delaySeconds":0,"message":"/a"}`,
		`{"delaySeconds":0,"message":"` + strings.Repeat("m", MaxMessageBytes+1) + `"}`,
		`{"delaySeconds":0,"notifyUser":"yes"}`,
	} {
		res, _ := handle(t, h, spec)
		if res.Status != protocol.StatusRejected || res.After != nil {
			t.Errorf("spec %.60s: status %s", spec, res.Status)
		}
	}
	if len(rb.snapshot()) != 0 {
		t.Fatal("a rejected job restarted the machine")
	}
	if n, _, _, _ := ui.Snapshot(); len(n) != 0 {
		t.Fatalf("a rejected job notified the user: %v", n)
	}
}

func TestRebootJobImmediateReportsBeforeRestarting(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	h := NewHandler(ui, rb)
	h.ResultGrace = 30 * time.Millisecond
	h.done = make(chan struct{})
	res, job := handle(t, h, protocol.RebootSpec{DelaySeconds: 0, Message: "Maintenance by Example IT.", NotifyUser: true})
	if res.Status != protocol.StatusSucceeded || res.After == nil {
		t.Fatalf("status %s, After nil=%v", res.Status, res.After == nil)
	}
	// Nothing restarts while the handler runs: only After triggers it.
	if len(rb.snapshot()) != 0 {
		t.Fatal("the machine was restarted before the job result could be sent")
	}
	notes, _, _, _ := ui.Snapshot()
	if len(notes) != 1 || notes[0] != "Restart required: Maintenance by Example IT. This computer will restart now." {
		t.Fatalf("notifications = %q", notes)
	}
	if !strings.Contains(job.Out.String(), "Restarting now.") {
		t.Fatalf("output = %q", job.Out.String())
	}
	sent := time.Now()
	res.After()
	<-h.done
	calls := rb.snapshot()
	if len(calls) != 1 || calls[0].delay != 0 || calls[0].message != "Maintenance by Example IT." {
		t.Fatalf("restart calls = %+v", calls)
	}
	if calls[0].at.Sub(sent) < 30*time.Millisecond {
		t.Fatalf("restart only %v after the result; the grace period was not kept", calls[0].at.Sub(sent))
	}
}

func TestRebootJobShortDelayWaitsInTheAgent(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	h := NewHandler(ui, rb)
	h.ResultGrace = time.Millisecond
	h.done = make(chan struct{})
	res, _ := handle(t, h, protocol.RebootSpec{DelaySeconds: 1})
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s", res.Status)
	}
	// notifyUser false: the user interface is not touched.
	if n, q, _, _ := ui.Snapshot(); len(n)+len(q) != 0 {
		t.Fatalf("UI used without notifyUser: %v %v", n, q)
	}
	start := time.Now()
	res.After()
	<-h.done
	if waited := time.Since(start); waited < 900*time.Millisecond {
		t.Fatalf("restarted after %v, want about 1s", waited)
	}
	if calls := rb.snapshot(); len(calls) != 1 || calls[0].delay != 0 {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestRebootJobLongDelayIsScheduledByTheOS(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	h := NewHandler(ui, rb)
	res, job := handle(t, h, protocol.RebootSpec{DelaySeconds: 600, Message: "Updates", NotifyUser: true})
	if res.Status != protocol.StatusSucceeded || res.After != nil {
		t.Fatalf("status %s", res.Status)
	}
	if calls := rb.snapshot(); len(calls) != 1 || calls[0].delay != 10*time.Minute || calls[0].message != "Updates" {
		t.Fatalf("calls = %+v", calls)
	}
	if notes, _, _, _ := ui.Snapshot(); len(notes) != 1 || !strings.Contains(notes[0], "in 10 minutes") {
		t.Fatalf("notifications = %q", notes)
	}
	if !strings.Contains(job.Out.String(), "Restart scheduled in 10 minutes.") {
		t.Fatalf("output = %q", job.Out.String())
	}
	// A scheduling failure is part of the job result.
	rb = newFakeRebooter()
	rb.err = errors.New("shutdown exited with code 1")
	res, _ = handle(t, NewHandler(ui, rb), protocol.RebootSpec{DelaySeconds: 600})
	if res.Status != protocol.StatusFailed || !strings.Contains(res.Message, "code 1") {
		t.Fatalf("status %s: %q", res.Status, res.Message)
	}
	// A system that cannot restart at all.
	rb = newFakeRebooter()
	rb.err = errors.Join(platform.ErrUnsupported, errors.New("no shutdown tool"))
	res, _ = handle(t, NewHandler(ui, rb), protocol.RebootSpec{DelaySeconds: 600})
	if res.Status != protocol.StatusUnsupported {
		t.Fatalf("status %s", res.Status)
	}
	res, _ = handle(t, NewHandler(ui, nil), protocol.RebootSpec{})
	if res.Status != protocol.StatusUnsupported {
		t.Fatalf("no rebooter: status %s", res.Status)
	}
	// A failing notification does not stop the restart.
	ui = userui.NewFake()
	ui.NotifyErr = errors.New("no display")
	rb = newFakeRebooter()
	res, _ = handle(t, NewHandler(ui, rb), protocol.RebootSpec{DelaySeconds: 120, NotifyUser: true})
	if res.Status != protocol.StatusSucceeded || len(rb.snapshot()) != 1 {
		t.Fatalf("notification failure: status %s", res.Status)
	}
}

func TestShutdownArgs(t *testing.T) {
	cases := []struct {
		delay   time.Duration
		message string
		unix    string
		windows string
	}{
		{0, "", "-r now", "/r /t 0"},
		{0, "Updates installed", "-r now|Updates installed", "/r /t 0|/c|Updates installed"},
		{30 * time.Second, "x", "-r +1|x", "/r /t 30|/c|x"},
		{60 * time.Second, "", "-r +1", "/r /t 60"},
		{61 * time.Second, "", "-r +2", "/r /t 61"},
		{10 * time.Minute, " padded ", "-r +10|padded", "/r /t 600|/c|padded"},
		{1500 * time.Millisecond, "", "-r +1", "/r /t 2"},
		{-5 * time.Second, "", "-r now", "/r /t 0"},
	}
	join := func(args []string) string {
		// The fixed arguments are joined with spaces, a message is its own element.
		fixed := 2
		if args[0] == "/r" {
			fixed = 3
		}
		return strings.Join(append([]string{strings.Join(args[:fixed], " ")}, args[fixed:]...), "|")
	}
	for _, c := range cases {
		if got := join(UnixShutdownArgs(c.delay, c.message)); got != c.unix {
			t.Errorf("unix %v %q: %s, want %s", c.delay, c.message, got, c.unix)
		}
		if got := join(WindowsShutdownArgs(c.delay, c.message)); got != c.windows {
			t.Errorf("windows %v %q: %s, want %s", c.delay, c.message, got, c.windows)
		}
	}
}

func TestShutdownRebooter(t *testing.T) {
	rec := &swtest.Recorder{}
	rb := &ShutdownRebooter{Plat: rec.Platform(nil), Lookup: swtest.Lookup("shutdown"), Args: UnixShutdownArgs}
	if err := rb.Reboot(context.Background(), 5*time.Minute, "Restart for updates"); err != nil {
		t.Fatal(err)
	}
	c := rec.Calls()[0]
	if c.Path != "/fake/bin/shutdown" || len(c.Args) != 3 || c.Args[0] != "-r" || c.Args[1] != "+5" || c.Args[2] != "Restart for updates" || c.AsUser != nil {
		t.Fatalf("command = %q %q", c.Path, c.Args)
	}
	rb.Args = WindowsShutdownArgs
	if err := rb.Reboot(context.Background(), 90*time.Second, "Restart for updates"); err != nil {
		t.Fatal(err)
	}
	if got := rec.Lines()[1]; got != "/fake/bin/shutdown /r /t 90 /c Restart for updates" {
		t.Fatalf("command = %s", got)
	}
	// The message can never become an option of the tool.
	for _, msg := range []string{"-h", "--poweroff", "/a", "x\ny"} {
		if err := rb.Reboot(context.Background(), 0, msg); err == nil {
			t.Errorf("message %q accepted", msg)
		}
	}
	if len(rec.Calls()) != 2 {
		t.Fatalf("an invalid message reached the tool: %v", rec.Lines())
	}
	// No shutdown tool: unsupported.
	rb = &ShutdownRebooter{Plat: rec.Platform(nil), Lookup: swtest.Lookup(), Args: UnixShutdownArgs}
	if err := rb.Reboot(context.Background(), 0, ""); !errors.Is(err, platform.ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
	// A failing tool is an error.
	rec = &swtest.Recorder{Respond: func(swtest.Call) swtest.Reply { return swtest.Reply{Exit: 1, Stderr: "shutdown: NOT super-user\n"} }}
	rb = &ShutdownRebooter{Plat: rec.Platform(nil), Lookup: swtest.Lookup("shutdown"), Args: UnixShutdownArgs}
	if err := rb.Reboot(context.Background(), 0, ""); err == nil || !strings.Contains(err.Error(), "NOT super-user") {
		t.Fatalf("err = %v", err)
	}
}

// ---- scheduler ----

func newTestScheduler(ui userui.UI, rb Rebooter, user *platform.User) *Scheduler {
	s := NewScheduler(ui, rb, &platform.Fake{User: user}, logging.Discard())
	s.StartDelay = 20 * time.Millisecond
	s.NoUserGrace = 60 * time.Millisecond
	s.AskTimeout = time.Second
	s.FinalWarning = 0
	return s
}

func wait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the reboot cycle did not end")
	}
}

func TestSchedulerNobodyLoggedIn(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	s := newTestScheduler(ui, rb, nil)
	start := time.Now()
	// A long deadline does not matter when nobody is there to be disturbed.
	done, started := s.Schedule(Plan{NotifyUser: true, Deferrals: 3, Deadline: time.Hour, Message: "Updates"})
	if !started {
		t.Fatal("not started")
	}
	wait(t, done)
	calls := rb.snapshot()
	if len(calls) != 1 || calls[0].delay != 0 || calls[0].message != "Updates" {
		t.Fatalf("calls = %+v", calls)
	}
	if waited := calls[0].at.Sub(start); waited < 80*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("restarted after %v, want start delay + grace (about 80ms)", waited)
	}
	if n, q, _, _ := ui.Snapshot(); len(n)+len(q) != 0 {
		t.Fatalf("UI used although nobody is logged in: %v %v", n, q)
	}
	if _, pending := s.Pending(); pending {
		t.Fatal("still pending after the restart")
	}
}

func TestSchedulerDeferralsThenDeadline(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	ui.Answer = false // the user always postpones
	s := newTestScheduler(ui, rb, alice)
	start := time.Now()
	const deadline = 600 * time.Millisecond
	done, _ := s.Schedule(Plan{NotifyUser: true, Deferrals: 2, Deadline: deadline, Message: "Updates were installed."})
	if d, pending := s.Pending(); !pending || d.Sub(start) < deadline {
		t.Fatalf("pending = %v %v", d, pending)
	}
	wait(t, done)
	calls := rb.snapshot()
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	// Restart at the deadline: not before, and not long after.
	if waited := calls[0].at.Sub(start); waited < deadline || waited > deadline+2*time.Second {
		t.Fatalf("restarted after %v, deadline %v", waited, deadline)
	}
	notes, questions, _, _ := ui.Snapshot()
	// Exactly as many prompts as deferrals, each offering fewer postponements.
	if len(questions) != 2 {
		t.Fatalf("prompts = %d: %+v", len(questions), questions)
	}
	if !strings.Contains(questions[0].Message, "postpone 2 more times") || !strings.Contains(questions[1].Message, "postpone 1 more time;") {
		t.Fatalf("prompt texts: %q / %q", questions[0].Message, questions[1].Message)
	}
	for _, q := range questions {
		if q.DefaultYes || q.YesLabel != "Restart now" || q.NoLabel != "Postpone" || q.Timeout <= 0 || q.Timeout > deadline/3+time.Millisecond {
			t.Fatalf("question = %+v", q)
		}
		if !strings.HasPrefix(q.Message, "Updates were installed. Restart now?") {
			t.Fatalf("question message = %q", q.Message)
		}
	}
	// Announcement, "no postponements left", final notice.
	if len(notes) != 3 || !strings.Contains(notes[0], "will restart at") || !strings.Contains(notes[1], "No postponements are left") || !strings.Contains(notes[2], "Save your work") {
		t.Fatalf("notifications = %q", notes)
	}
}

func TestSchedulerUserRestartsNow(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake() // answers yes
	s := newTestScheduler(ui, rb, alice)
	start := time.Now()
	done, _ := s.Schedule(Plan{NotifyUser: true, Deferrals: 3, Deadline: time.Hour})
	wait(t, done)
	calls := rb.snapshot()
	if len(calls) != 1 || calls[0].at.Sub(start) > 5*time.Second {
		t.Fatalf("calls = %+v", calls)
	}
	if _, q, _, _ := ui.Snapshot(); len(q) != 1 {
		t.Fatalf("prompts = %d", len(q))
	}
}

func TestSchedulerPromptTimeoutCountsAsDeferral(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	ui.TimesOut = true // the user never answers
	s := newTestScheduler(ui, rb, alice)
	start := time.Now()
	done, _ := s.Schedule(Plan{NotifyUser: true, Deferrals: 1, Deadline: 400 * time.Millisecond})
	wait(t, done)
	calls := rb.snapshot()
	if len(calls) != 1 || calls[0].at.Sub(start) < 400*time.Millisecond {
		t.Fatalf("calls = %+v after %v", calls, time.Since(start))
	}
	if _, q, _, _ := ui.Snapshot(); len(q) != 1 {
		t.Fatalf("prompts = %d", len(q))
	}
}

func TestSchedulerSilentAndForcedVariants(t *testing.T) {
	// notifyUser false: no UI at all, restart at the deadline.
	rb := newFakeRebooter()
	ui := userui.NewFake()
	s := newTestScheduler(ui, rb, alice)
	start := time.Now()
	done, _ := s.Schedule(Plan{NotifyUser: false, Deferrals: 5, Deadline: 200 * time.Millisecond})
	wait(t, done)
	if calls := rb.snapshot(); len(calls) != 1 || calls[0].at.Sub(start) < 200*time.Millisecond {
		t.Fatalf("silent: %+v", calls)
	}
	if n, q, _, _ := ui.Snapshot(); len(n)+len(q) != 0 {
		t.Fatalf("silent plan used the UI: %v %v", n, q)
	}

	// Deadline zero (force, immediately): no prompts even with deferrals.
	rb = newFakeRebooter()
	ui = userui.NewFake()
	s = newTestScheduler(ui, rb, alice)
	done, _ = s.Schedule(Plan{NotifyUser: true, Deferrals: 3, Deadline: 0, Message: "Now"})
	wait(t, done)
	if n, q, _, _ := ui.Snapshot(); len(rb.snapshot()) != 1 || len(q) != 0 || len(n) != 2 {
		t.Fatalf("immediate: calls %d, prompts %d, notes %q", len(rb.snapshot()), len(q), n)
	}

	// A user is logged in but cannot be asked (no desktop): no prompts, the deadline stands.
	rb = newFakeRebooter()
	ui = userui.NewFake()
	ui.Asked = false
	s = newTestScheduler(ui, rb, alice)
	start = time.Now()
	done, _ = s.Schedule(Plan{NotifyUser: true, Deferrals: 3, Deadline: 300 * time.Millisecond})
	wait(t, done)
	if calls := rb.snapshot(); len(calls) != 1 || calls[0].at.Sub(start) < 300*time.Millisecond {
		t.Fatalf("cannot ask: %+v", calls)
	}
	if _, q, _, _ := ui.Snapshot(); len(q) != 1 {
		t.Fatalf("cannot ask: prompts = %d", len(q))
	}

	// The operating system shows the last countdown.
	rb = newFakeRebooter()
	ui = userui.NewFake()
	s = newTestScheduler(ui, rb, alice)
	s.FinalWarning = 100 * time.Millisecond
	start = time.Now()
	done, _ = s.Schedule(Plan{NotifyUser: true, Deadline: 300 * time.Millisecond})
	wait(t, done)
	calls := rb.snapshot()
	if len(calls) != 1 || calls[0].delay != 100*time.Millisecond {
		t.Fatalf("final warning: %+v", calls)
	}
	if waited := calls[0].at.Sub(start); waited < 200*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("final warning handed to the OS after %v, want about 220ms", waited)
	}
}

func TestSchedulerCustomRestartAndFallback(t *testing.T) {
	// The plan's own restart action is used instead of the Rebooter.
	rb := newFakeRebooter()
	s := newTestScheduler(userui.NewFake(), rb, nil)
	ran := make(chan struct{}, 1)
	done, _ := s.Schedule(Plan{Restart: func(context.Context) error { ran <- struct{}{}; return nil }})
	wait(t, done)
	if len(ran) != 1 || len(rb.snapshot()) != 0 {
		t.Fatalf("custom restart: ran %d, rebooter %d", len(ran), len(rb.snapshot()))
	}
	// If it fails, the system restart is used after all.
	done, _ = s.Schedule(Plan{Message: "m", Restart: func(context.Context) error { return errors.New("needs a volume owner") }})
	wait(t, done)
	if calls := rb.snapshot(); len(calls) != 1 || calls[0].delay != 0 || calls[0].message != "m" {
		t.Fatalf("fallback: %+v", calls)
	}
}

func TestSchedulerOnePendingCycleEarlierDeadlineWins(t *testing.T) {
	rb := newFakeRebooter()
	ui := userui.NewFake()
	ui.Answer = false
	s := newTestScheduler(ui, rb, alice)
	first, started := s.Schedule(Plan{NotifyUser: false, Deadline: time.Hour})
	if !started {
		t.Fatal("first not started")
	}
	// A later deadline does not replace the pending restart.
	if _, started := s.Schedule(Plan{Deadline: 2 * time.Hour}); started {
		t.Fatal("a later deadline replaced the pending restart")
	}
	// An earlier one does.
	second, started := s.Schedule(Plan{Deadline: 100 * time.Millisecond})
	if !started {
		t.Fatal("an earlier deadline was ignored")
	}
	wait(t, first) // cancelled
	wait(t, second)
	if calls := rb.snapshot(); len(calls) != 1 {
		t.Fatalf("restarts = %d, want exactly one", len(calls))
	}
	// Cancel abandons a pending restart.
	done, _ := s.Schedule(Plan{Deadline: time.Hour})
	s.Cancel()
	wait(t, done)
	if calls := rb.snapshot(); len(calls) != 1 {
		t.Fatalf("a cancelled cycle restarted the machine: %d", len(calls))
	}
	if _, pending := s.Pending(); pending {
		t.Fatal("pending after cancel")
	}
}

func TestDescribeDelay(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                      "now",
		30 * time.Second:       "in 30 seconds",
		90 * time.Second:       "in 90 seconds",
		10 * time.Minute:       "in 10 minutes",
		3 * time.Hour:          "in 3 hours",
		500 * time.Millisecond: "now",
	} {
		if got := DescribeDelay(d); got != want {
			t.Errorf("DescribeDelay(%v) = %q, want %q", d, got, want)
		}
	}
}
