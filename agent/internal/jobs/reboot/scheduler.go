package reboot

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// Scheduler defaults.
const (
	// DefaultNoUserGrace is how long the scheduler waits before restarting a
	// machine nobody is logged in to.
	DefaultNoUserGrace = 60 * time.Second
	// DefaultAskTimeout is how long one "restart now or postpone" prompt
	// stays open; no answer counts as a postponement.
	DefaultAskTimeout = 5 * time.Minute
	// DefaultFinalWarning is the countdown the operating system itself shows
	// (shutdown's own warning) before the restart at the deadline.
	DefaultFinalWarning = 60 * time.Second
)

// Plan is one restart to carry out under a reboot policy.
type Plan struct {
	// NotifyUser shows notifications and, with Deferrals, prompts. Without
	// it the restart happens silently at the deadline.
	NotifyUser bool
	// Deferrals is how many times the user may postpone.
	Deferrals int
	// Deadline is the latest moment of the restart, measured from Schedule.
	Deadline time.Duration
	// Message is the organisation's text shown to the user (may be empty).
	Message string
	// Restart, if set, performs the restart instead of the Rebooter (macOS
	// uses it to apply staged system updates). If it fails the Rebooter is
	// used after all.
	Restart func(ctx context.Context) error
}

// Scheduler runs the reboot policy of patch installation: notify the
// logged-in user, let them postpone up to Deferrals times (the prompts are
// spread evenly over the time to the deadline), and restart at the deadline
// at the latest. When nobody is logged in the machine restarts after a short
// grace period.
//
// The pending restart is kept in memory only: an agent restart cancels a
// pending deferral cycle (the server sees "pendingReboot" in the next
// heartbeat and can dispatch the reboot again). At most one cycle is
// pending; of two requests the one with the earlier deadline wins.
type Scheduler struct {
	UI       userui.UI
	Rebooter Rebooter
	Plat     platform.Platform
	Log      *slog.Logger

	// StartDelay is waited first so that the job result is on the wire
	// before anything visible happens.
	StartDelay   time.Duration
	NoUserGrace  time.Duration
	AskTimeout   time.Duration
	FinalWarning time.Duration

	mu       sync.Mutex
	cancel   context.CancelFunc
	deadline time.Time
	gen      uint64
}

// NewScheduler returns a scheduler with the production timings.
func NewScheduler(ui userui.UI, r Rebooter, plat platform.Platform, log *slog.Logger) *Scheduler {
	if log == nil {
		log = logging.Discard()
	}
	return &Scheduler{
		UI: ui, Rebooter: r, Plat: plat, Log: log,
		StartDelay:   DefaultResultGrace,
		NoUserGrace:  DefaultNoUserGrace,
		AskTimeout:   DefaultAskTimeout,
		FinalWarning: DefaultFinalWarning,
	}
}

// Schedule starts the policy for plan. started is false when an already
// pending restart with an earlier (or equal) deadline stays in charge. done
// is closed when the cycle of this call has ended (restart requested,
// cancelled or superseded); it is nil when started is false.
func (s *Scheduler) Schedule(p Plan) (done <-chan struct{}, started bool) {
	if p.Deferrals < 0 {
		p.Deferrals = 0
	}
	if p.Deadline < 0 {
		p.Deadline = 0
	}
	start := time.Now().Add(s.StartDelay)
	deadline := start.Add(p.Deadline)

	s.mu.Lock()
	if s.cancel != nil {
		if !deadline.Before(s.deadline) {
			s.mu.Unlock()
			return nil, false
		}
		s.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.deadline = cancel, deadline
	s.gen++
	gen := s.gen
	s.mu.Unlock()

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		s.run(ctx, p, start, deadline)
		s.mu.Lock()
		if s.gen == gen {
			s.cancel = nil
		}
		s.mu.Unlock()
		cancel()
	}()
	return ch, true
}

// Pending returns the deadline of the pending restart, if any.
func (s *Scheduler) Pending() (deadline time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline, s.cancel != nil
}

// Cancel abandons the pending restart, if any.
func (s *Scheduler) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}

// sleepUntil waits until t; it returns false when ctx ended first.
func sleepUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func minDuration(a time.Duration, rest ...time.Duration) time.Duration {
	for _, d := range rest {
		if d < a {
			a = d
		}
	}
	return a
}

func clockTime(t time.Time) string {
	if time.Until(t) > 20*time.Hour {
		return t.Local().Format("Mon 2 Jan 15:04")
	}
	return t.Local().Format("15:04")
}

func joinText(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, " ")
}

func (s *Scheduler) userPresent(ctx context.Context) bool {
	if s.Plat == nil {
		return false
	}
	_, err := s.Plat.ConsoleUser(ctx)
	return err == nil
}

func (s *Scheduler) notify(ctx context.Context, text string) {
	if s.UI == nil {
		return
	}
	if err := s.UI.Notify(ctx, NotificationTitle, text); err != nil {
		s.Log.Warn("could not show restart notification", slog.Any("error", err))
	}
}

func (s *Scheduler) run(ctx context.Context, p Plan, start, deadline time.Time) {
	if !sleepUntil(ctx, start) {
		return
	}
	if !s.userPresent(ctx) {
		grace := minDuration(s.NoUserGrace, time.Until(deadline))
		s.Log.Warn("restart pending: nobody is logged in", slog.Duration("grace", grace))
		if !sleepUntil(ctx, time.Now().Add(grace)) {
			return
		}
		s.restart(ctx, p, 0)
		return
	}
	s.Log.Warn("restart pending", slog.Time("deadline", deadline), slog.Int("deferrals", p.Deferrals), slog.Bool("notify_user", p.NotifyUser))

	if p.NotifyUser {
		s.notify(ctx, joinText(p.Message, fmt.Sprintf("This computer will restart at %s (%s).", clockTime(deadline), DescribeDelay(time.Until(deadline)))))
		if p.Deferrals > 0 && p.Deadline > 0 && s.UI != nil {
			if s.prompt(ctx, p, start, deadline) {
				return
			}
			if ctx.Err() != nil {
				return
			}
		}
	}

	// Restart at the deadline; the last stretch is the OS's own countdown.
	warning := time.Duration(0)
	if p.NotifyUser {
		warning = minDuration(s.FinalWarning, time.Until(deadline))
		if warning < 0 {
			warning = 0
		}
	}
	if !sleepUntil(ctx, deadline.Add(-warning)) {
		return
	}
	if p.NotifyUser {
		s.notify(ctx, joinText(p.Message, "This computer will restart "+DescribeDelay(warning)+". Save your work."))
	}
	s.restart(ctx, p, warning)
}

// prompt runs the deferral prompts. It returns true when the user chose to
// restart now (the restart was requested).
func (s *Scheduler) prompt(ctx context.Context, p Plan, start, deadline time.Time) bool {
	slot := p.Deadline / time.Duration(p.Deferrals+1)
	left := p.Deferrals
	for k := 0; left > 0; k++ {
		if !sleepUntil(ctx, start.Add(time.Duration(k)*slot)) {
			return false
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		plural := "s"
		if left == 1 {
			plural = ""
		}
		yes, asked, err := s.UI.Confirm(ctx, userui.Question{
			Title: NotificationTitle,
			Message: joinText(p.Message, fmt.Sprintf(
				"Restart now? You can postpone %d more time%s; the computer restarts automatically at %s.",
				left, plural, clockTime(deadline))),
			YesLabel:   "Restart now",
			NoLabel:    "Postpone",
			Timeout:    minDuration(slot, s.AskTimeout, remaining),
			DefaultYes: false,
		})
		if err != nil || !asked {
			// Nobody could be asked: no further prompts, the deadline stands.
			if err != nil {
				s.Log.Warn("could not ask the user about the restart", slog.Any("error", err))
			}
			return false
		}
		if yes {
			s.Log.Info("user chose to restart now")
			s.restart(ctx, p, 0)
			return true
		}
		left--
		s.Log.Info("user postponed the restart", slog.Int("deferrals_left", left))
		if left == 0 {
			s.notify(ctx, joinText(p.Message, fmt.Sprintf("No postponements are left. This computer will restart at %s.", clockTime(deadline))))
		}
	}
	return false
}

// restart performs the restart: the plan's own action if it has one (after
// waiting out the warning), otherwise the Rebooter with the warning as the
// operating system's countdown.
func (s *Scheduler) restart(ctx context.Context, p Plan, warning time.Duration) {
	if ctx.Err() != nil {
		return
	}
	// The restart itself is not abandoned half-way by a later Cancel.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
	defer cancel()
	if p.Restart != nil {
		if !sleepUntil(ctx, time.Now().Add(warning)) {
			return
		}
		err := p.Restart(rctx)
		if err == nil {
			return
		}
		s.Log.Warn("restart through the update tool failed; using the system restart", slog.Any("error", err))
		warning = 0
	}
	if s.Rebooter == nil {
		s.Log.Error("restart needed but this system has no way to restart")
		return
	}
	s.Log.Warn("restarting the computer", slog.Duration("os_countdown", warning))
	if err := s.Rebooter.Reboot(rctx, warning, p.Message); err != nil {
		s.Log.Error("restart failed", slog.Any("error", err))
	}
}
