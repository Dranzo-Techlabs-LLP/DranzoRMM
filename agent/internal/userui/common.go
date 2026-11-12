package userui

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Limits and timings shared by the per-OS implementations. Everything shown
// to the user is bounded and every helper process has a deadline.
const (
	defaultConfirmTimeout = 60 * time.Second
	maxConfirmTimeout     = 10 * time.Minute
	notifyTimeout         = 20 * time.Second
	lookupTimeout         = 15 * time.Second

	maxTitleLen   = 120
	maxMessageLen = 1000
	maxLabelLen   = 30

	defaultYesLabel = "Yes"
	defaultNoLabel  = "No"

	// EndSessionLabel is the caption of the indicator's button.
	EndSessionLabel = "End session"
)

// Environment variable names used to hand text to helper processes. Text is
// always passed as data (argv or environment), never spliced into a script.
const (
	EnvTitle     = "DRANZO_UI_TITLE"
	EnvMessage   = "DRANZO_UI_MESSAGE"
	EnvEndLabel  = "DRANZO_UI_END_LABEL"
	EnvParentPID = "DRANZO_UI_PARENT_PID"
)

// cleanLine makes untrusted text safe to show on one line: valid UTF-8, no
// control or formatting characters, trimmed and capped at limit bytes.
func cleanLine(s string, limit int) string { return clean(s, limit, false) }

// cleanText is cleanLine for multi-line messages: line feeds are kept.
func cleanText(s string, limit int) string { return clean(s, limit, true) }

func clean(s string, limit int, keepNewlines bool) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' && keepNewlines:
			b.WriteRune('\n')
		case r == '\n' || r == '\t' || r == ' ':
			b.WriteRune(' ')
		case unicode.IsPrint(r):
			// Letters, marks, numbers, punctuation and symbols.
			b.WriteRune(r)
		case unicode.Is(unicode.Zs, r):
			b.WriteRune(' ')
		default:
			// Control characters, bidirectional overrides, line separators and
			// other invisible formatting runes could disguise who is
			// connecting: drop them.
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > limit {
		out = out[:limit]
		for len(out) > 0 && !utf8.ValidString(out) {
			out = out[:len(out)-1]
		}
		out = strings.TrimSpace(out)
	}
	return out
}

// normalize applies defaults and limits to a question.
func normalize(q Question) Question {
	q.Title = cleanLine(q.Title, maxTitleLen)
	q.Message = cleanText(q.Message, maxMessageLen)
	q.YesLabel = cleanLine(q.YesLabel, maxLabelLen)
	q.NoLabel = cleanLine(q.NoLabel, maxLabelLen)
	if q.YesLabel == "" {
		q.YesLabel = defaultYesLabel
	}
	if q.NoLabel == "" {
		q.NoLabel = defaultNoLabel
	}
	if q.YesLabel == q.NoLabel {
		// Two identical buttons could not be told apart.
		q.YesLabel, q.NoLabel = defaultYesLabel, defaultNoLabel
	}
	if q.Timeout <= 0 {
		q.Timeout = defaultConfirmTimeout
	}
	if q.Timeout > maxConfirmTimeout {
		q.Timeout = maxConfirmTimeout
	}
	if q.Timeout < time.Second {
		q.Timeout = time.Second
	}
	return q
}

// timeoutSeconds is the question timeout in whole seconds (rounded up).
func timeoutSeconds(q Question) int {
	return int((q.Timeout + time.Second - 1) / time.Second)
}

// consoleUser returns the logged-in console user, or nil when nobody is
// logged in (which is not an error for any UI operation).
func consoleUser(ctx context.Context, plat platform.Platform) (*platform.User, error) {
	cctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	u, err := plat.ConsoleUser(cctx)
	if err != nil {
		if errors.Is(err, platform.ErrNoConsoleUser) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

// runTarget decides how a helper is started for u: nil (run as the agent
// itself) when the agent already is that user, which happens in development
// when the agent runs unprivileged in the user's own session.
func runTarget(u *platform.User, euid int) *platform.User {
	if u != nil && u.UID != "" && euid > 0 && u.UID == strconv.Itoa(euid) {
		return nil
	}
	return u
}

func currentEUID() int { return os.Geteuid() }

// capture runs cmd with bounded stdout / stderr buffers.
func capture(ctx context.Context, plat platform.Platform, cmd platform.Command) (stdout, stderr string, code int, err error) {
	var out, errb limitedBuffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	code, err = plat.Run(ctx, cmd)
	return out.String(), errb.String(), code, err
}

// limitedBuffer keeps at most 64 KiB; helpers print a word or two.
type limitedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := 64<<10 - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// ---- indicator loop ----

// showResult is how one run of an indicator helper ended.
type showResult int

const (
	// showEnded: the user chose "End session".
	showEnded showResult = iota
	// showClosed: the user closed the indicator window without that choice;
	// it is shown again.
	showClosed
)

// indicatorTimings are the loop delays (shortened in tests).
type indicatorTimings struct {
	// startTimeout is how long ShowIndicator waits for the first helper to
	// report that the indicator is on screen.
	startTimeout time.Duration
	// presumeReady: a helper that cannot report readiness is presumed to be
	// visible once it has been running this long. Zero means the helper must
	// report readiness itself.
	presumeReady time.Duration
	// quickExit: a helper with a close button that returns sooner than this
	// counts as failed rather than as closed by the user.
	quickExit time.Duration
	// reshowDelay is the pause before a closed indicator is shown again.
	reshowDelay time.Duration
	// retryDelay is the pause after a failure (multiplied by the number of
	// consecutive failures).
	retryDelay time.Duration
	// userPoll is how often the loop looks for a console user while nobody
	// is logged in.
	userPoll time.Duration
	// maxFailures consecutive failures while a user is logged in mean the
	// indicator cannot be shown.
	maxFailures int
}

func defaultIndicatorTimings() indicatorTimings {
	return indicatorTimings{
		startTimeout: 30 * time.Second,
		presumeReady: time.Second,
		quickExit:    time.Second,
		reshowDelay:  time.Second,
		retryDelay:   2 * time.Second,
		userPoll:     10 * time.Second,
		maxFailures:  4,
	}
}

// showFunc shows the indicator once to u and blocks until it goes away or
// ctx ends. It calls ready once the indicator is on screen, if it can tell.
type showFunc func(ctx context.Context, u *platform.User, ready func()) (showResult, error)

// runIndicator implements ShowIndicator on top of a blocking helper:
//
//   - nobody logged in: shown=false, nothing keeps running;
//   - shown=true is returned only after the first helper reported (or is
//     presumed) to be on screen;
//   - the helper is restarted for as long as the indicator is wanted, so a
//     closed or crashed indicator comes back and a user who logs in later
//     gets one too;
//   - "End session" closes ended;
//   - if the indicator can no longer be shown to a logged-in user, ended is
//     closed as well: a remote session must not continue without a visible
//     indicator (fail closed).
//
// The indicator lives until stop is called; ctx only bounds the set-up.
func runIndicator(ctx context.Context, plat platform.Platform, tm indicatorTimings, show showFunc) (stop func(), ended <-chan struct{}, shown bool, err error) {
	noop := func() {}
	never := make(chan struct{})
	u, err := consoleUser(ctx, plat)
	if err != nil {
		return noop, never, false, err
	}
	if u == nil {
		return noop, never, false, nil
	}

	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	endedCh := make(chan struct{})
	done := make(chan struct{})
	first := make(chan error, 1)
	reportFirst := func(e error) {
		select {
		case first <- e:
		default:
		}
	}
	var endOnce sync.Once
	end := func() { endOnce.Do(func() { close(endedCh) }) }

	go func() {
		defer close(done)
		failures := 0
		for attempt := 0; loopCtx.Err() == nil; attempt++ {
			if attempt > 0 {
				// Somebody else may be sitting at the device by now.
				nu, uerr := consoleUser(loopCtx, plat)
				if loopCtx.Err() != nil {
					return
				}
				if uerr == nil && nu == nil {
					failures = 0
					if !sleepCtx(loopCtx, tm.userPoll) {
						return
					}
					continue
				}
				if uerr == nil {
					u = nu
				}
			}
			res, serr := showOnce(loopCtx, u, tm, show, func() { reportFirst(nil) })
			if loopCtx.Err() != nil {
				return
			}
			switch {
			case serr != nil:
				failures++
				reportFirst(serr)
				if failures >= tm.maxFailures {
					end()
					return
				}
				if !sleepCtx(loopCtx, time.Duration(failures)*tm.retryDelay) {
					return
				}
			case res == showEnded:
				reportFirst(nil)
				end()
				return
			default:
				failures = 0
				if !sleepCtx(loopCtx, tm.reshowDelay) {
					return
				}
			}
		}
	}()

	var stopOnce sync.Once
	stop = func() {
		stopOnce.Do(func() {
			cancel()
			<-done
		})
	}

	timeout := time.NewTimer(tm.startTimeout)
	defer timeout.Stop()
	select {
	case ferr := <-first:
		if ferr != nil {
			stop()
			return noop, never, false, ferr
		}
		return stop, endedCh, true, nil
	case <-timeout.C:
		stop()
		return noop, never, false, errors.New("the session indicator did not appear in time")
	case <-ctx.Done():
		stop()
		return noop, never, false, ctx.Err()
	}
}

// showOnce runs one helper. A helper that cannot report readiness is
// presumed visible after tm.presumeReady; one that exits before that without
// "End session" has failed.
func showOnce(ctx context.Context, u *platform.User, tm indicatorTimings, show showFunc, ready func()) (showResult, error) {
	var once sync.Once
	markReady := func() { once.Do(ready) }
	stopTimer := func() bool { return true }
	if tm.presumeReady > 0 {
		t := time.AfterFunc(tm.presumeReady, markReady)
		stopTimer = t.Stop
	}
	started := time.Now()
	res, err := show(ctx, u, markReady)
	stopTimer()
	if err != nil {
		return res, err
	}
	if res == showClosed && time.Since(started) < tm.quickExit {
		return res, errors.New("the session indicator closed immediately")
	}
	return res, nil
}

// markerWriter calls fn the first time marker appears in the stream.
type markerWriter struct {
	mu     sync.Mutex
	marker string
	seen   string
	fn     func()
	done   bool
}

func (m *markerWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done {
		return len(p), nil
	}
	m.seen += string(p)
	if strings.Contains(m.seen, m.marker) {
		m.done = true
		m.seen = ""
		m.fn()
	} else if len(m.seen) > 4096 {
		m.seen = m.seen[len(m.seen)-len(m.marker):]
	}
	return len(p), nil
}

// sleepCtx waits for d; it returns false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
