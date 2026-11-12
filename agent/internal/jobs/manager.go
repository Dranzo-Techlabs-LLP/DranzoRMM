package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Reasons used in job.ack accepted=false.
const (
	ReasonBusy      = "busy"
	ReasonDuplicate = "duplicate"
	ReasonShutdown  = "shutting_down"
)

var (
	errCancelled = errors.New("job cancelled")
	errShutdown  = errors.New("agent shutting down")
)

// ErrInvalidJobRunID is returned by Dispatch when the dispatch cannot even be
// acknowledged because its jobRunId is not a UUID.
var ErrInvalidJobRunID = errors.New("jobRunId is not a valid id")

// Options configures a Manager.
type Options struct {
	// DeviceID may also be set later with SetDeviceID (it is only known
	// after enrollment, while handlers are registered before that).
	DeviceID string
	// MaxConcurrent is the number of jobs run at once (default 4);
	// QueueSize the number waiting in memory (default 32).
	MaxConcurrent int
	QueueSize     int
	Sender        Sender
	Logger        *slog.Logger
	Platform      platform.Platform
	Blobs         BlobClient
	Sessions      SessionLookup
	TempDir       string
	// FlushInterval overrides the 250 ms output flush interval (tests).
	FlushInterval time.Duration
}

type job struct {
	d         protocol.JobDispatch
	timeout   time.Duration
	maxOutput int64
	sessionID string
	// immediate, when set, is sent as the result without running a handler.
	immediate *Result
	acked     chan struct{}

	mu              sync.Mutex
	cancel          context.CancelCauseFunc
	cancelRequested bool
}

// Manager owns the handler registry and the run queue.
type Manager struct {
	opts Options
	log  *slog.Logger
	ctx  context.Context
	stop context.CancelCauseFunc
	wg   sync.WaitGroup

	mu       sync.Mutex
	deviceID string
	handlers map[string]Handler
	running  map[string]*job
	queue    []*job
	closed   bool
}

// SetDeviceID sets the device id used for log correlation and JobContext.
func (m *Manager) SetDeviceID(id string) {
	m.mu.Lock()
	m.deviceID = id
	m.mu.Unlock()
}

// SetMaxConcurrent changes the number of jobs run at once (config.json
// maxConcurrentJobs). It affects jobs dispatched from now on.
func (m *Manager) SetMaxConcurrent(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.opts.MaxConcurrent = n
	m.mu.Unlock()
}

func (m *Manager) device() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deviceID
}

// NewManager creates a manager. ctx bounds every job and all result delivery.
func NewManager(ctx context.Context, opts Options) *Manager {
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = protocol.DefaultMaxConcurrent
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = protocol.DefaultJobQueueSize
	}
	if opts.Logger == nil {
		opts.Logger = logging.Discard()
	}
	if opts.Sessions == nil {
		opts.Sessions = NoSessions{}
	}
	mctx, stop := context.WithCancelCause(ctx)
	return &Manager{
		opts:     opts,
		log:      opts.Logger,
		ctx:      mctx,
		stop:     stop,
		deviceID: opts.DeviceID,
		handlers: map[string]Handler{},
		running:  map[string]*job{},
	}
}

// Register adds the handler for a job kind. It panics on an invalid or
// duplicate kind (a programming error at start-up).
func (m *Manager) Register(kind string, h Handler) {
	if !protocol.ValidKind(kind) || h == nil {
		panic("jobs: invalid handler registration for kind " + kind)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.handlers[kind]; dup {
		panic("jobs: duplicate handler for kind " + kind)
	}
	m.handlers[kind] = h
}

// Kinds returns the sorted list of registered job kinds (hello.capabilities).
func (m *Manager) Kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	kinds := make([]string, 0, len(m.handlers))
	for k := range m.handlers {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// Active returns the number of running and queued jobs.
func (m *Manager) Active() (running, queued int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.running), len(m.queue)
}

// validate checks the dispatch-level fields and returns the immediate result
// for a job that must not run (nil if it may run).
func (m *Manager) validate(j *job) *Result {
	d := j.d
	rej := func(format string, args ...any) *Result {
		r := Rejected(format, args...)
		return &r
	}
	if !protocol.ValidKind(d.Kind) {
		return rej("invalid job kind")
	}
	switch {
	case d.TimeoutSeconds == 0:
		j.timeout = protocol.DefaultJobTimeout * time.Second
	case d.TimeoutSeconds < 0 || d.TimeoutSeconds > protocol.MaxJobTimeoutSeconds:
		return rej("timeoutSeconds must be between 1 and %d", protocol.MaxJobTimeoutSeconds)
	default:
		j.timeout = time.Duration(d.TimeoutSeconds) * time.Second
	}
	switch {
	case d.MaxOutputBytes == 0:
		j.maxOutput = protocol.DefaultMaxOutputBytes
	case d.MaxOutputBytes < 0:
		return rej("maxOutputBytes must not be negative")
	case d.MaxOutputBytes > protocol.HardMaxOutputBytes:
		j.maxOutput = protocol.HardMaxOutputBytes
	default:
		j.maxOutput = d.MaxOutputBytes
	}
	if d.SessionID != nil && *d.SessionID != "" {
		if !protocol.ValidUUID(*d.SessionID) {
			return rej("sessionId is not a valid id")
		}
		j.sessionID = *d.SessionID
	}
	if len(d.Spec) > 0 && string(d.Spec) != "null" && d.Spec[0] != '{' {
		return rej("spec must be an object")
	}
	m.mu.Lock()
	_, known := m.handlers[d.Kind]
	m.mu.Unlock()
	if !known {
		r := Result{Status: protocol.StatusUnsupported, Message: fmt.Sprintf("job kind %q is not supported by this agent build", d.Kind)}
		return &r
	}
	return nil
}

// Dispatch accepts a VERIFIED job.dispatch: it sends job.ack at once and then
// runs or queues the job. ackCtx bounds only the delivery of the ack (the
// connection the dispatch arrived on).
func (m *Manager) Dispatch(ackCtx context.Context, d protocol.JobDispatch) error {
	if !protocol.ValidUUID(d.JobRunID) {
		return ErrInvalidJobRunID
	}
	j := &job{d: d, acked: make(chan struct{})}
	j.immediate = m.validate(j)
	log := logging.ForJob(m.log, m.device(), d.JobRunID)

	refusal := ""
	startNow := false
	m.mu.Lock()
	switch {
	case m.closed:
		refusal = ReasonShutdown
	case m.running[d.JobRunID] != nil || m.queuedLocked(d.JobRunID):
		refusal = ReasonDuplicate
	case j.immediate != nil:
		// Answered directly; takes no run slot.
	case len(m.running) < m.opts.MaxConcurrent:
		m.running[d.JobRunID] = j
		startNow = true
	case len(m.queue) < m.opts.QueueSize:
		m.queue = append(m.queue, j)
	default:
		refusal = ReasonBusy
	}
	if refusal == "" {
		m.wg.Add(1)
	}
	m.mu.Unlock()

	if refusal != "" {
		log.Warn("job refused", slog.String("kind", d.Kind), slog.String("reason", refusal))
		return m.opts.Sender.Send(ackCtx, protocol.TypeJobAck, protocol.JobAck{JobRunID: d.JobRunID, Accepted: false, Reason: refusal})
	}

	log.Info("job accepted", slog.String("kind", d.Kind), slog.Bool("queued", !startNow && j.immediate == nil))
	// The ack always precedes any output or result of the job.
	ackErr := m.opts.Sender.Send(ackCtx, protocol.TypeJobAck, protocol.JobAck{JobRunID: d.JobRunID, Accepted: true})
	close(j.acked)
	switch {
	case j.immediate != nil:
		go func() {
			defer m.wg.Done()
			now := time.Now().UTC()
			m.sendResult(j, *j.immediate, Summary{OutputSHA256: emptySHA256}, now, now)
		}()
	case startNow:
		go m.run(j)
	}
	return ackErr
}

var emptySHA256 = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

func (m *Manager) queuedLocked(id string) bool {
	for _, q := range m.queue {
		if q.d.JobRunID == id {
			return true
		}
	}
	return false
}

// Cancel handles a VERIFIED job.cancel. It reports whether the job was known.
func (m *Manager) Cancel(jobRunID string) bool {
	m.mu.Lock()
	if j := m.running[jobRunID]; j != nil {
		m.mu.Unlock()
		j.mu.Lock()
		j.cancelRequested = true
		cancel := j.cancel
		j.mu.Unlock()
		if cancel != nil {
			cancel(errCancelled)
		}
		return true
	}
	for i, q := range m.queue {
		if q.d.JobRunID != jobRunID {
			continue
		}
		m.queue = append(m.queue[:i], m.queue[i+1:]...)
		m.mu.Unlock()
		go func() {
			defer m.wg.Done()
			<-q.acked
			now := time.Now().UTC()
			m.sendResult(q, Result{Status: protocol.StatusCancelled, Message: "cancelled before start"}, Summary{OutputSHA256: emptySHA256}, now, now)
		}()
		return true
	}
	m.mu.Unlock()
	return false
}

func (m *Manager) run(j *job) {
	defer m.wg.Done()
	<-j.acked
	d := j.d
	log := logging.ForJob(m.log, m.device(), d.JobRunID)

	ctx, cancelCause := context.WithCancelCause(m.ctx)
	ctx, cancelTimeout := context.WithTimeout(ctx, j.timeout)
	defer cancelTimeout()
	defer cancelCause(nil)
	j.mu.Lock()
	j.cancel = cancelCause
	already := j.cancelRequested
	j.mu.Unlock()
	if already {
		cancelCause(errCancelled)
	}

	m.mu.Lock()
	h := m.handlers[d.Kind]
	m.mu.Unlock()

	out := NewOutputStream(m.ctx, d.JobRunID, j.maxOutput, m.opts.FlushInterval, func(ctx context.Context, o protocol.JobOutput) error {
		return m.opts.Sender.Send(ctx, protocol.TypeJobOutput, o)
	})
	jc := &JobContext{
		Ctx:            ctx,
		DeviceID:       m.device(),
		JobRunID:       d.JobRunID,
		Kind:           d.Kind,
		Spec:           d.Spec,
		SessionID:      j.sessionID,
		TimeoutSeconds: int(j.timeout / time.Second),
		Stdout:         out.Writer(protocol.StreamStdout),
		Stderr:         out.Writer(protocol.StreamStderr),
		Log:            log,
		Platform:       m.opts.Platform,
		Blobs:          m.opts.Blobs,
		Sessions:       m.opts.Sessions,
		TempDir:        m.opts.TempDir,
	}

	started := time.Now().UTC()
	log.Info("job started", slog.String("kind", d.Kind), slog.Duration("timeout", j.timeout))
	res := safeHandle(h, jc)
	finished := time.Now().UTC()
	sum := out.Close()

	// Cancellation and timeout override whatever a killed handler reported.
	if res.Status != protocol.StatusSucceeded && ctx.Err() != nil {
		switch cause := context.Cause(ctx); {
		case errors.Is(cause, errCancelled):
			res = Result{Status: protocol.StatusCancelled, Message: "cancelled", Result: res.Result}
		case errors.Is(cause, context.DeadlineExceeded):
			res = Result{Status: protocol.StatusTimeout, Message: fmt.Sprintf("timed out after %d seconds", jc.TimeoutSeconds), Result: res.Result}
		case errors.Is(cause, errShutdown):
			res = Result{Status: protocol.StatusFailed, Message: "agent shutting down", Result: res.Result}
		}
	}
	if !validStatus(res.Status) {
		res = Failed("handler returned an invalid status")
	}
	log.Info("job finished", slog.String("kind", d.Kind), slog.String("status", res.Status),
		slog.Int64("output_bytes", sum.OutputBytes), slog.Bool("truncated", sum.Truncated),
		slog.Duration("duration", finished.Sub(started)))
	m.sendResult(j, res, sum, started, finished)
	if res.After != nil {
		res.After()
	}

	// Free the slot and start the next queued job.
	m.mu.Lock()
	delete(m.running, d.JobRunID)
	var next *job
	if len(m.queue) > 0 && !m.closed {
		next = m.queue[0]
		m.queue = m.queue[1:]
		m.running[next.d.JobRunID] = next
	}
	m.mu.Unlock()
	if next != nil {
		go m.run(next)
	}
}

func validStatus(s string) bool {
	switch s {
	case protocol.StatusSucceeded, protocol.StatusFailed, protocol.StatusTimeout,
		protocol.StatusCancelled, protocol.StatusRejected, protocol.StatusUnsupported:
		return true
	}
	return false
}

// safeHandle runs the handler and converts a panic into a failed result so
// one faulty handler cannot take the agent down.
func safeHandle(h Handler, jc *JobContext) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			jc.Log.Error("job handler panicked", slog.String("panic", fmt.Sprint(r)))
			res = Failed("internal error in job handler")
		}
	}()
	return h.Handle(jc)
}

func (m *Manager) sendResult(j *job, res Result, sum Summary, started, finished time.Time) {
	msg := res.Message
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	payload := protocol.JobResult{
		JobRunID:     j.d.JobRunID,
		Status:       res.Status,
		ExitCode:     res.ExitCode,
		Message:      msg,
		Truncated:    sum.Truncated,
		OutputBytes:  sum.OutputBytes,
		OutputSHA256: sum.OutputSHA256,
		StartedAt:    started,
		FinishedAt:   finished,
		Result:       res.Result,
	}
	if err := m.opts.Sender.Send(m.ctx, protocol.TypeJobResult, payload); err != nil {
		logging.ForJob(m.log, m.device(), j.d.JobRunID).Error("job result not delivered", slog.Any("error", err))
	}
}

// Shutdown refuses new jobs, cancels the running ones (killing their process
// trees) and waits up to wait for them to end.
func (m *Manager) Shutdown(wait time.Duration) {
	m.mu.Lock()
	m.closed = true
	queued := m.queue
	m.queue = nil
	running := make([]*job, 0, len(m.running))
	for _, j := range m.running {
		running = append(running, j)
	}
	m.mu.Unlock()
	for range queued {
		m.wg.Done()
	}
	for _, j := range running {
		j.mu.Lock()
		cancel := j.cancel
		j.mu.Unlock()
		if cancel != nil {
			cancel(errShutdown)
		}
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
	m.stop(errShutdown)
}
