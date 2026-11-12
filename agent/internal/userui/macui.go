package userui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// macOS implementation: osascript run inside the console user's GUI session
// (platform.Run with AsUser: "launchctl asuser <uid> sudo -u #<uid> ...").
//
// Every string shown to the user is handed to the script as an osascript
// argument and read through "on run argv"; the AppleScript source below is
// constant, so no text from the server is ever parsed as code.
//
// This file has no build tag so that the command construction is unit-tested
// on every OS; only new_darwin.go selects it.

const osascriptPath = "/usr/bin/osascript"

// macIndicatorReady is logged by the indicator script right before the
// dialog is put on screen.
const macIndicatorReady = "dranzo-indicator-showing"

// AppleScript sources. They are constants: never build them with fmt.
const (
	macNotifyScript = `on run argv
	display notification (item 2 of argv) with title (item 1 of argv)
end run`

	// Arguments: title, message, yes label, no label, default label, seconds.
	// Prints "yes", "no" or "timeout".
	macConfirmScript = `on run argv
	set dlgTitle to item 1 of argv
	set dlgText to item 2 of argv
	set yesLabel to item 3 of argv
	set noLabel to item 4 of argv
	set defLabel to item 5 of argv
	set secs to (item 6 of argv) as integer
	try
		tell me to activate
	end try
	set r to display dialog dlgText with title dlgTitle buttons {noLabel, yesLabel} default button defLabel giving up after secs with icon caution
	if gave up of r then return "timeout"
	if button returned of r is yesLabel then return "yes"
	return "no"
end run`

	// Arguments: title, message, end label. The dialog has a single button and
	// no default button, so it stays on screen until the user ends the session
	// (or the agent stops the helper). Prints "ended".
	macIndicatorScript = `on run argv
	set dlgTitle to item 1 of argv
	set dlgText to item 2 of argv
	set endLabel to item 3 of argv
	try
		tell me to activate
	end try
	log "` + macIndicatorReady + `"
	display dialog dlgText with title dlgTitle buttons {endLabel} with icon caution
	return "ended"
end run`
)

type macUI struct {
	plat    platform.Platform
	euid    func() int
	timings indicatorTimings
}

func newMacUI(plat platform.Platform) *macUI {
	return &macUI{plat: plat, euid: currentEUID, timings: defaultIndicatorTimings()}
}

// osascriptArgs builds the argv: the constant script, "--" (so that no value
// can be mistaken for an osascript option), then the values.
func osascriptArgs(script string, values ...string) []string {
	args := make([]string, 0, len(values)+3)
	args = append(args, "-e", script, "--")
	return append(args, values...)
}

func (m *macUI) command(u *platform.User, script string, values ...string) platform.Command {
	return platform.Command{
		Path:   osascriptPath,
		Args:   osascriptArgs(script, values...),
		Dir:    "/",
		AsUser: runTarget(u, m.euid()),
	}
}

// Notify implements UI.
func (m *macUI) Notify(ctx context.Context, title, message string) error {
	u, err := consoleUser(ctx, m.plat)
	if err != nil || u == nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	_, stderr, code, err := capture(cctx, m.plat, m.command(u, macNotifyScript,
		cleanLine(title, maxTitleLen), cleanText(message, maxMessageLen)))
	if err != nil {
		return fmt.Errorf("show notification: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("show notification: osascript exit code %d: %s", code, firstLine(stderr))
	}
	return nil
}

// Confirm implements UI.
func (m *macUI) Confirm(ctx context.Context, q Question) (yes, asked bool, err error) {
	u, err := consoleUser(ctx, m.plat)
	if err != nil || u == nil {
		return false, false, err
	}
	q = normalize(q)
	def := q.NoLabel
	if q.DefaultYes {
		def = q.YesLabel
	}
	// The dialog gives up by itself; the context deadline is only a backstop.
	cctx, cancel := context.WithTimeout(ctx, q.Timeout+30*time.Second)
	defer cancel()
	stdout, stderr, code, err := capture(cctx, m.plat, m.command(u, macConfirmScript,
		q.Title, q.Message, q.YesLabel, q.NoLabel, def, strconv.Itoa(timeoutSeconds(q))))
	if err != nil {
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			// The dialog never answered: treat like a timeout.
			return q.DefaultYes, true, nil
		}
		return false, false, fmt.Errorf("show prompt: %w", err)
	}
	if code != 0 {
		return false, false, fmt.Errorf("show prompt: osascript exit code %d: %s", code, firstLine(stderr))
	}
	switch strings.TrimSpace(stdout) {
	case "yes":
		return true, true, nil
	case "no":
		return false, true, nil
	case "timeout":
		return q.DefaultYes, true, nil
	default:
		return false, false, errors.New("show prompt: unexpected osascript output")
	}
}

// ShowIndicator implements UI. Baseline until a signed menu-bar helper
// exists: a dialog "Remote session active: ..." with a single "End session"
// button that stays on screen for the whole session and is shown again if
// its process goes away.
func (m *macUI) ShowIndicator(ctx context.Context, title, message string) (stop func(), ended <-chan struct{}, shown bool, err error) {
	title = cleanLine(title, maxTitleLen)
	message = cleanText(message, maxMessageLen)
	show := func(ctx context.Context, u *platform.User, ready func()) (showResult, error) {
		cmd := m.command(u, macIndicatorScript, title, message, EndSessionLabel)
		var out, errb limitedBuffer
		cmd.Stdout = &out
		cmd.Stderr = &teeWriter{a: &errb, b: &markerWriter{marker: macIndicatorReady, fn: ready}}
		code, err := m.plat.Run(ctx, cmd)
		if err != nil {
			return showClosed, fmt.Errorf("show indicator: %w", err)
		}
		if code == 0 && strings.TrimSpace(out.String()) == "ended" {
			return showEnded, nil
		}
		// The dialog has no other way to close: anything else is a failure.
		return showClosed, fmt.Errorf("show indicator: osascript exit code %d: %s", code,
			firstLine(strings.ReplaceAll(errb.String(), macIndicatorReady, "")))
	}
	tm := m.timings
	// osascript logs the marker just before the dialog appears; give the
	// window server a moment before the session is reported as visible.
	tm.presumeReady = 0
	return runIndicator(ctx, m.plat, tm, func(ctx context.Context, u *platform.User, ready func()) (showResult, error) {
		return show(ctx, u, func() { time.AfterFunc(300*time.Millisecond, ready) })
	})
}

// teeWriter writes to both writers (errors are ignored: both are in-memory).
type teeWriter struct {
	a, b interface{ Write([]byte) (int, error) }
}

func (t *teeWriter) Write(p []byte) (int, error) {
	_, _ = t.a.Write(p)
	_, _ = t.b.Write(p)
	return len(p), nil
}

// firstLine returns the first non-empty line of s, capped for error messages.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > 200 {
				line = line[:200]
			}
			return line
		}
	}
	return ""
}
