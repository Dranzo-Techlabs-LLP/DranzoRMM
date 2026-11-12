// Package reboot implements the "reboot" job kind (PROTOCOL.md section 6.2)
// and the reboot scheduler used by patch installation (notify the logged-in
// user, allow deferrals, restart at the latest at a deadline).
//
// The operating system restart itself is behind the Rebooter interface so
// that tests never restart anything. A restart is always announced: the
// job result is sent before it happens and the logged-in user is told when
// the job asks for it.
package reboot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// Limits of a reboot request.
const (
	// MaxDelaySeconds is the longest accepted delay (7 days).
	MaxDelaySeconds = 7 * 24 * 60 * 60
	// MaxMessageBytes is the longest accepted message (the Windows shutdown
	// comment is limited to 512 characters).
	MaxMessageBytes = 512
	// osScheduleThreshold: a delay of at least this long is handed to the
	// operating system's own shutdown timer inside the job, so a failure to
	// schedule it is reported in the job result. Shorter delays are waited
	// out by the agent after the result was sent.
	osScheduleThreshold = 60 * time.Second
	// DefaultResultGrace is the minimum time between handing the job result
	// to the connection and restarting, so the result reaches the server.
	DefaultResultGrace = 3 * time.Second
)

// Rebooter restarts the operating system.
type Rebooter interface {
	// Reboot asks the OS to restart after delay, showing message to logged-in
	// users where the OS supports it. It returns once the restart is
	// scheduled. It returns platform.ErrUnsupported (wrapped) when this
	// system has no way to restart.
	Reboot(ctx context.Context, delay time.Duration, message string) error
}

// NewRebooter returns the Rebooter of this operating system.
func NewRebooter(plat platform.Platform) Rebooter { return newOSRebooter(plat) }

// ValidMessage checks a user-visible restart message: bounded, no control
// characters, and not starting with "-" or "/" (it is passed to the
// shutdown tool as an argument and must never look like one of its options).
func ValidMessage(msg string) error {
	if len(msg) > MaxMessageBytes {
		return fmt.Errorf("message exceeds %d bytes", MaxMessageBytes)
	}
	if strings.IndexFunc(msg, unicode.IsControl) >= 0 {
		return errors.New("message contains control characters")
	}
	if t := strings.TrimSpace(msg); strings.HasPrefix(t, "-") || strings.HasPrefix(t, "/") {
		return errors.New("message must not start with - or /")
	}
	return nil
}

// Validate checks every field of the spec.
func Validate(spec *protocol.RebootSpec) error {
	if spec.DelaySeconds < 0 || spec.DelaySeconds > MaxDelaySeconds {
		return fmt.Errorf("delaySeconds must be between 0 and %d", MaxDelaySeconds)
	}
	return ValidMessage(spec.Message)
}

// Handler implements the "reboot" job kind.
type Handler struct {
	UI       userui.UI
	Rebooter Rebooter
	// ResultGrace overrides DefaultResultGrace (tests).
	ResultGrace time.Duration
	// done, if set, is closed when the deferred restart call returned (tests).
	done chan struct{}
}

// NewHandler returns the reboot handler.
func NewHandler(ui userui.UI, r Rebooter) *Handler {
	return &Handler{UI: ui, Rebooter: r, ResultGrace: DefaultResultGrace}
}

// DescribeDelay renders a delay for a notification ("now", "in 30 seconds",
// "in 5 minutes").
func DescribeDelay(d time.Duration) string {
	switch {
	case d < time.Second:
		return "now"
	case d < 2*time.Minute:
		return fmt.Sprintf("in %d seconds", int(d.Round(time.Second)/time.Second))
	case d < 2*time.Hour:
		return fmt.Sprintf("in %d minutes", int(d.Round(time.Minute)/time.Minute))
	default:
		return fmt.Sprintf("in %d hours", int(d.Round(time.Hour)/time.Hour))
	}
}

// NotificationTitle is the title of every restart notification.
const NotificationTitle = "Restart required"

func notificationText(message string, delay time.Duration) string {
	text := "This computer will restart " + DescribeDelay(delay) + "."
	if message = strings.TrimSpace(message); message != "" {
		text = message + " " + text
	}
	return text
}

// Handle implements jobs.Handler.
func (h *Handler) Handle(jc *jobs.JobContext) jobs.Result {
	var spec protocol.RebootSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if err := Validate(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if h.Rebooter == nil {
		return jobs.Unsupported("restart")
	}
	delay := time.Duration(spec.DelaySeconds) * time.Second
	jc.Log.Warn("restart requested by the server", slog.Int("delay_seconds", spec.DelaySeconds), slog.Bool("notify_user", spec.NotifyUser))

	if spec.NotifyUser && h.UI != nil {
		if err := h.UI.Notify(jc.Ctx, NotificationTitle, notificationText(spec.Message, delay)); err != nil {
			jc.Log.Warn("could not notify the user about the restart", slog.Any("error", err))
			fmt.Fprintf(jc.Stderr, "could not notify the logged-in user: %v\n", err)
		}
	}

	if delay >= osScheduleThreshold {
		// The OS keeps the timer; scheduling errors are part of the result.
		if err := h.Rebooter.Reboot(jc.Ctx, delay, spec.Message); err != nil {
			return jobs.FromError(err)
		}
		fmt.Fprintf(jc.Stdout, "Restart scheduled %s.\n", DescribeDelay(delay))
		res := jobs.Succeeded()
		res.Message = "restart scheduled " + DescribeDelay(delay)
		return res
	}

	// Short delay: report first, then restart.
	wait := delay
	if wait < h.ResultGrace {
		wait = h.ResultGrace
	}
	fmt.Fprintf(jc.Stdout, "Restarting %s.\n", DescribeDelay(delay))
	log := jc.Log
	res := jobs.Succeeded()
	res.Message = "restarting " + DescribeDelay(delay)
	res.After = func() {
		go func() {
			if h.done != nil {
				defer close(h.done)
			}
			time.Sleep(wait)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if err := h.Rebooter.Reboot(ctx, 0, spec.Message); err != nil {
				log.Error("restart failed", slog.Any("error", err))
			}
		}()
	}
	return res
}
