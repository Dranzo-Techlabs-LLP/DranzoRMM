package userui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Linux implementation.
//
//   - Graphical login (logind session of type x11 / wayland): zenity, or
//     kdialog when zenity is not installed, started as the console user with
//     that session's DISPLAY / WAYLAND_DISPLAY / XDG_RUNTIME_DIR /
//     DBUS_SESSION_BUS_ADDRESS; notifications through notify-send.
//   - Text-only login: a visible notice written to the user's terminals at the
//     start and the end of a session (and repeated while it lasts). A prompt
//     cannot be shown there, so Confirm reports asked=false.
//   - Nobody logged in (headless server): asked=false / shown=false.
//
// Texts are passed as single "--option=value" argv elements (or after "--"),
// never through a shell. This file has no build tag so that the command
// construction is unit-tested on every OS; only new_linux.go selects it.

// loginSession is the subset of `loginctl show-session` used here.
type loginSession struct {
	ID      string
	Name    string
	Type    string
	Display string
	TTY     string
	State   string
	Class   string
	Active  bool
	Remote  bool
}

// loginctlProps are the properties requested from `loginctl show-session`.
var loginctlProps = []string{"Id", "Name", "Type", "Display", "TTY", "State", "Class", "Active", "Remote"}

// parseSessionIDs extracts the session ids from `loginctl list-sessions --no-legend`.
func parseSessionIDs(output string) []string {
	var ids []string
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !sessionIDPattern.MatchString(f[0]) {
			continue
		}
		ids = append(ids, f[0])
		if len(ids) >= 256 {
			break
		}
	}
	return ids
}

// parseLoginSession parses the KEY=VALUE output of `loginctl show-session`.
func parseLoginSession(output string) loginSession {
	var s loginSession
	for _, line := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			s.ID = v
		case "Name":
			s.Name = v
		case "Type":
			s.Type = v
		case "Display":
			s.Display = v
		case "TTY":
			s.TTY = v
		case "State":
			s.State = v
		case "Class":
			s.Class = v
		case "Active":
			s.Active = v == "yes"
		case "Remote":
			s.Remote = v == "yes"
		}
	}
	return s
}

var (
	sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	// Values taken from logind or from a process environment are only passed
	// on when they look like what they claim to be.
	displayPattern  = regexp.MustCompile(`^[A-Za-z0-9.:_/\[\]-]{1,128}$`)
	waylandPattern  = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)
	ttyPattern      = regexp.MustCompile(`^(tty[0-9]{1,3}|ttyS[0-9]{1,3}|pts/[0-9]{1,6})$`)
	envValuePattern = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,512}$`)
)

// desktop describes where the console user can be reached.
type desktop struct {
	// Graphical is true when the user has an x11 / wayland session.
	Graphical bool
	// Env are the variables a GUI helper needs (KEY=VALUE).
	Env []string
	// TTYs are the device paths of the user's text terminals.
	TTYs []string
}

// pickDesktop derives the desktop from the user's logind sessions and from
// the environment of one of the user's graphical processes (may be nil).
func pickDesktop(u *platform.User, sessions []loginSession, procEnv map[string]string) desktop {
	var d desktop
	var graphical *loginSession
	for i := range sessions {
		s := &sessions[i]
		if s.Name != u.Name || s.State == "closing" || (s.Class != "" && s.Class != "user") {
			continue
		}
		switch s.Type {
		case "x11", "wayland", "mir":
			if graphical == nil || (s.Active && !graphical.Active) {
				graphical = s
			}
		default:
			if ttyPattern.MatchString(s.TTY) {
				d.TTYs = append(d.TTYs, "/dev/"+s.TTY)
			}
		}
	}
	if graphical == nil {
		return d
	}
	d.Graphical = true
	env := map[string]string{}
	if u.UID != "" {
		runtimeDir := "/run/user/" + u.UID
		env["XDG_RUNTIME_DIR"] = runtimeDir
		env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + runtimeDir + "/bus"
	}
	if graphical.Type == "wayland" {
		env["WAYLAND_DISPLAY"] = "wayland-0"
	}
	if displayPattern.MatchString(graphical.Display) {
		env["DISPLAY"] = graphical.Display
	} else if graphical.Type == "x11" {
		env["DISPLAY"] = ":0"
	}
	// What the user's own desktop processes use is more precise than the
	// defaults above (Xauthority location, a second display, a custom bus).
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_CURRENT_DESKTOP"} {
		v, ok := procEnv[k]
		if !ok || !envValuePattern.MatchString(v) {
			continue
		}
		if k == "DISPLAY" && !displayPattern.MatchString(v) || k == "WAYLAND_DISPLAY" && !waylandPattern.MatchString(v) {
			continue
		}
		env[k] = v
	}
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_CURRENT_DESKTOP"} {
		if v, ok := env[k]; ok {
			d.Env = append(d.Env, k+"="+v)
		}
	}
	return d
}

// ---- command lines ----

func zenityQuestionArgs(q Question) []string {
	args := []string{
		"--question",
		"--title=" + q.Title,
		"--text=" + q.Message,
		"--ok-label=" + q.YesLabel,
		"--cancel-label=" + q.NoLabel,
		"--timeout=" + strconv.Itoa(timeoutSeconds(q)),
		"--no-markup",
		"--width=420",
	}
	if !q.DefaultYes {
		args = append(args, "--default-cancel")
	}
	return args
}

func zenityIndicatorArgs(title, message string) []string {
	return []string{
		"--info",
		"--title=" + title,
		"--text=" + message,
		"--ok-label=" + EndSessionLabel,
		"--no-markup",
		"--width=420",
	}
}

func kdialogQuestionArgs(q Question) []string {
	return []string{
		"--title=" + q.Title,
		"--yes-label=" + q.YesLabel,
		"--no-label=" + q.NoLabel,
		"--yesno=" + q.Message,
	}
}

// kdialogKeepLabel is the second button of the kdialog indicator. A kdialog
// message box reports "closed" and "OK" alike, so a yes/no box is used:
// closing it (or "Keep session") brings the indicator back, only the
// explicit button ends the session.
const kdialogKeepLabel = "Keep session"

func kdialogIndicatorArgs(title, message string) []string {
	return []string{
		"--title=" + title,
		"--yes-label=" + EndSessionLabel,
		"--no-label=" + kdialogKeepLabel,
		"--yesno=" + message,
	}
}

// notifyBody neutralises the markup some notification servers interpret.
func notifyBody(message string) string {
	return strings.NewReplacer("<", "‹", ">", "›").Replace(message)
}

func notifySendArgs(title, message string) []string {
	return []string{"--app-name=DranzoRMM", "--urgency=normal", "--expire-time=15000", "--", title, notifyBody(message)}
}

func zenityNotifyArgs(title, message string) []string {
	return []string{"--notification", "--text=" + title + "\n" + message}
}

// ttyNotice formats a notice for a text terminal.
func ttyNotice(lines ...string) string {
	var b strings.Builder
	b.WriteString("\r\n")
	for _, l := range lines {
		for _, part := range strings.Split(l, "\n") {
			if part = strings.TrimSpace(part); part != "" {
				b.WriteString("*** DranzoRMM: " + part + " ***\r\n")
			}
		}
	}
	return b.String()
}

// ---- implementation ----

type linuxUI struct {
	plat platform.Platform
	euid func() int
	// look resolves a helper binary (exec.LookPath).
	look func(name string) (string, error)
	// procEnv returns the environment of one of the user's graphical
	// processes (nil when none was found).
	procEnv func(uid string) map[string]string
	// writeTTY writes text to a terminal device.
	writeTTY func(path, text string) error
	// endFile creates the file whose removal by the user ends a session
	// announced on a text terminal. It returns "" when no such file can be
	// offered.
	endFile func(u *platform.User) string
	timings indicatorTimings
	// ttyReminder is how often the notice is repeated on text terminals.
	ttyReminder time.Duration
	ttyPoll     time.Duration
}

func newLinuxUI(plat platform.Platform) *linuxUI {
	return &linuxUI{
		plat:        plat,
		euid:        currentEUID,
		look:        exec.LookPath,
		procEnv:     func(string) map[string]string { return nil },
		writeTTY:    func(string, string) error { return errors.New("terminal notices are not available") },
		endFile:     func(*platform.User) string { return "" },
		timings:     defaultIndicatorTimings(),
		ttyReminder: 5 * time.Minute,
		ttyPoll:     2 * time.Second,
	}
}

// sessions lists the logind sessions (nil when loginctl is unavailable).
func (l *linuxUI) sessions(ctx context.Context) []loginSession {
	loginctl, err := l.look("loginctl")
	if err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	out, _, code, err := capture(cctx, l.plat, platform.Command{Path: loginctl, Args: []string{"list-sessions", "--no-legend"}})
	if err != nil || code != 0 {
		return nil
	}
	var list []loginSession
	for _, id := range parseSessionIDs(out) {
		args := []string{"show-session", id}
		for _, p := range loginctlProps {
			args = append(args, "-p", p)
		}
		detail, _, code, err := capture(cctx, l.plat, platform.Command{Path: loginctl, Args: args})
		if err != nil || code != 0 {
			continue
		}
		list = append(list, parseLoginSession(detail))
	}
	return list
}

// reach finds the console user and how to reach them. u is nil when nobody
// is logged in.
func (l *linuxUI) reach(ctx context.Context) (*platform.User, desktop, error) {
	u, err := consoleUser(ctx, l.plat)
	if err != nil || u == nil {
		return nil, desktop{}, err
	}
	return u, pickDesktop(u, l.sessions(ctx), l.procEnv(u.UID)), nil
}

func (l *linuxUI) helper(names ...string) (name, path string) {
	for _, n := range names {
		if p, err := l.look(n); err == nil {
			return n, p
		}
	}
	return "", ""
}

func (l *linuxUI) guiCommand(u *platform.User, d desktop, path string, args []string) platform.Command {
	dir := "/"
	if u.Home != "" {
		dir = u.Home
	}
	return platform.Command{Path: path, Args: args, Env: d.Env, Dir: dir, AsUser: runTarget(u, l.euid())}
}

func (l *linuxUI) writeAll(d desktop, text string) (written int) {
	for _, tty := range d.TTYs {
		if l.writeTTY(tty, text) == nil {
			written++
		}
	}
	return written
}

// Notify implements UI.
func (l *linuxUI) Notify(ctx context.Context, title, message string) error {
	u, d, err := l.reach(ctx)
	if err != nil || u == nil {
		return err
	}
	title = cleanLine(title, maxTitleLen)
	message = cleanText(message, maxMessageLen)
	if d.Graphical {
		name, path := l.helper("notify-send", "zenity", "kdialog")
		var args []string
		switch name {
		case "notify-send":
			args = notifySendArgs(title, message)
		case "zenity":
			args = zenityNotifyArgs(title, message)
		case "kdialog":
			args = []string{"--title=" + title, "--passivepopup=" + message, "15"}
		}
		if name != "" {
			cctx, cancel := context.WithTimeout(ctx, notifyTimeout)
			defer cancel()
			_, stderr, code, err := capture(cctx, l.plat, l.guiCommand(u, d, path, args))
			if err == nil && code == 0 {
				return nil
			}
			if len(d.TTYs) == 0 {
				if err != nil {
					return fmt.Errorf("show notification: %w", err)
				}
				return fmt.Errorf("show notification: %s exit code %d: %s", name, code, firstLine(stderr))
			}
		}
	}
	if len(d.TTYs) == 0 {
		return errors.New("show notification: no notification tool (notify-send, zenity, kdialog) and no terminal to write to")
	}
	if l.writeAll(d, ttyNotice(title, message)) == 0 {
		return errors.New("show notification: could not write to the user's terminal")
	}
	return nil
}

// Confirm implements UI.
func (l *linuxUI) Confirm(ctx context.Context, q Question) (yes, asked bool, err error) {
	u, d, err := l.reach(ctx)
	if err != nil || u == nil {
		return false, false, err
	}
	if !d.Graphical {
		// Text-only login: there is no way to show a prompt.
		return false, false, nil
	}
	q = normalize(q)
	name, path := l.helper("zenity", "kdialog")
	switch name {
	case "zenity":
		cctx, cancel := context.WithTimeout(ctx, q.Timeout+30*time.Second)
		defer cancel()
		_, stderr, code, err := capture(cctx, l.plat, l.guiCommand(u, d, path, zenityQuestionArgs(q)))
		if err != nil {
			if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				return q.DefaultYes, true, nil
			}
			return false, false, fmt.Errorf("show prompt: %w", err)
		}
		switch {
		case code == 0:
			return true, true, nil
		case code == 5:
			return q.DefaultYes, true, nil
		case code == 1 && !displayFailure(stderr):
			return false, true, nil
		default:
			return false, false, fmt.Errorf("show prompt: zenity exit code %d: %s", code, firstLine(stderr))
		}
	case "kdialog":
		// kdialog has no timeout option: the deadline closes the dialog.
		cctx, cancel := context.WithTimeout(ctx, q.Timeout)
		defer cancel()
		_, stderr, code, err := capture(cctx, l.plat, l.guiCommand(u, d, path, kdialogQuestionArgs(q)))
		if err != nil {
			if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				return q.DefaultYes, true, nil
			}
			return false, false, fmt.Errorf("show prompt: %w", err)
		}
		switch {
		case code == 0:
			return true, true, nil
		case code == 1 && !displayFailure(stderr):
			return false, true, nil
		default:
			return false, false, fmt.Errorf("show prompt: kdialog exit code %d: %s", code, firstLine(stderr))
		}
	default:
		// A desktop without zenity or kdialog: no way to show a prompt.
		return false, false, nil
	}
}

// displayFailure recognises a toolkit that could not open the display (which
// exits with the same code as "No").
func displayFailure(stderr string) bool {
	s := strings.ToLower(stderr)
	for _, needle := range []string{"cannot open display", "unable to init", "could not connect to display", "failed to open display", "no protocol specified"} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// ShowIndicator implements UI. Baseline until a tray helper exists: a
// zenity / kdialog window "Remote session active: ..." whose only button is
// "End session"; closing the window brings it back. On a text-only login
// the notice is written to the user's terminals instead.
func (l *linuxUI) ShowIndicator(ctx context.Context, title, message string) (stop func(), ended <-chan struct{}, shown bool, err error) {
	title = cleanLine(title, maxTitleLen)
	message = cleanText(message, maxMessageLen)
	// Decide once, up front, whether there is any way to show an indicator.
	u, d, err := l.reach(ctx)
	if err != nil || u == nil {
		return func() {}, make(chan struct{}), false, err
	}
	if name, _ := l.helper("zenity", "kdialog"); (!d.Graphical || name == "") && len(d.TTYs) == 0 {
		return func() {}, make(chan struct{}), false, errors.New("show indicator: no dialog tool (zenity, kdialog) and no terminal to write to")
	}
	return runIndicator(ctx, l.plat, l.timings, func(ctx context.Context, _ *platform.User, ready func()) (showResult, error) {
		// Look again on every (re)start: the user may have switched between
		// a desktop and a text console, or somebody else may have logged in.
		u, d, err := l.reach(ctx)
		if err != nil {
			return showClosed, err
		}
		if u == nil {
			return showClosed, errors.New("show indicator: the user logged out")
		}
		if d.Graphical {
			if name, path := l.helper("zenity", "kdialog"); name != "" {
				args := zenityIndicatorArgs(title, message)
				if name == "kdialog" {
					args = kdialogIndicatorArgs(title, message)
				}
				_, stderr, code, err := capture(ctx, l.plat, l.guiCommand(u, d, path, args))
				switch {
				case err != nil:
					return showClosed, fmt.Errorf("show indicator: %w", err)
				case code == 0:
					return showEnded, nil
				case (code == 1 || code == 2 && name == "kdialog") && !displayFailure(stderr):
					return showClosed, nil
				default:
					return showClosed, fmt.Errorf("show indicator: %s exit code %d: %s", name, code, firstLine(stderr))
				}
			}
		}
		return l.ttyIndicator(ctx, u, d, title, message, ready)
	})
}

// ttyIndicator announces the session on the user's text terminals, repeats
// the notice while it lasts and announces its end. The user ends the session
// by removing the file named in the notice.
func (l *linuxUI) ttyIndicator(ctx context.Context, u *platform.User, d desktop, title, message string, ready func()) (showResult, error) {
	if len(d.TTYs) == 0 {
		return showClosed, errors.New("show indicator: no terminal to write to")
	}
	endPath := l.endFile(u)
	lines := []string{title, message}
	if endPath != "" {
		lines = append(lines, "To end the remote session now, run: rm "+endPath)
		defer func() { _ = os.Remove(endPath) }()
	}
	notice := ttyNotice(lines...)
	if l.writeAll(d, notice) == 0 {
		return showClosed, errors.New("show indicator: could not write to the user's terminal")
	}
	ready()
	poll := time.NewTicker(l.ttyPoll)
	defer poll.Stop()
	remind := time.NewTicker(l.ttyReminder)
	defer remind.Stop()
	for {
		select {
		case <-ctx.Done():
			l.writeAll(d, ttyNotice("The remote session has ended."))
			return showClosed, ctx.Err()
		case <-remind.C:
			l.writeAll(d, notice)
		case <-poll.C:
			if endPath == "" {
				continue
			}
			if _, err := os.Lstat(endPath); errors.Is(err, os.ErrNotExist) {
				l.writeAll(d, ttyNotice("Ending the remote session as requested."))
				return showEnded, nil
			}
		}
	}
}

// endFilePrefix starts the name of the "remove me to end the session" file.
const endFilePrefix = "dranzormm-remote-session-"
