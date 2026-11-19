package userui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// nasty contains what must always arrive as data: quotes, a command
// substitution, shell / AppleScript / PowerShell metacharacters, something
// that looks like an option and a line break.
const nasty = `Jane "Doe" 'x' $(touch /tmp/pwned) ` + "`id`" + ` ; & | < > \ -e do shell script "id" $env:USERNAME %PATH% {braces}` + "\nsecond line"

var (
	nastyLine = strings.ReplaceAll(nasty, "\n", " ")
	testUser  = &platform.User{Name: "alice", UID: "501", GID: "20", Home: "/Users/alice", SessionID: 3}
)

// recorder is a platform.Fake RunFunc that records every command.
type recorder struct {
	mu    sync.Mutex
	cmds  []platform.Command
	reply func(n int, cmd platform.Command, ctx context.Context) (int, error)
}

func (r *recorder) run(ctx context.Context, cmd platform.Command) (int, error) {
	r.mu.Lock()
	r.cmds = append(r.cmds, cmd)
	n := len(r.cmds)
	reply := r.reply
	r.mu.Unlock()
	if reply == nil {
		return 0, nil
	}
	return reply(n, cmd, ctx)
}

func (r *recorder) all() []platform.Command {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]platform.Command(nil), r.cmds...)
}

func (r *recorder) count() int { return len(r.all()) }

func fastTimings() indicatorTimings {
	return indicatorTimings{
		startTimeout: 2 * time.Second,
		presumeReady: 30 * time.Millisecond,
		quickExit:    10 * time.Millisecond,
		reshowDelay:  5 * time.Millisecond,
		retryDelay:   5 * time.Millisecond,
		userPoll:     10 * time.Millisecond,
		maxFailures:  3,
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestClean(t *testing.T) {
	cases := []struct{ in, line, text string }{
		{"plain", "plain", "plain"},
		{"  a\tb\r\nc  ", "a b c", "a b\nc"},
		{"bell\x07 esc\x1b[31m nul\x00", "bell esc[31m nul", "bell esc[31m nul"},
		{"rtl\u202eevil\u200b", "rtlevil", "rtlevil"},
		{"nbsp\u00a0x\u2028y", "nbsp xy", "nbsp xy"},
		{"bad\xff\xfeutf8", "badutf8", "badutf8"},
		{"Zoë (Example IT) <b>&amp;", "Zoë (Example IT) <b>&amp;", "Zoë (Example IT) <b>&amp;"},
	}
	for _, c := range cases {
		if got := cleanLine(c.in, 100); got != c.line {
			t.Errorf("cleanLine(%q) = %q, want %q", c.in, got, c.line)
		}
		if got := cleanText(c.in, 100); got != c.text {
			t.Errorf("cleanText(%q) = %q, want %q", c.in, got, c.text)
		}
	}
	if got := cleanLine(strings.Repeat("é", 100), 11); got != "ééééé" {
		t.Errorf("cap must not split a rune: %q", got)
	}
}

func TestNormalize(t *testing.T) {
	q := normalize(Question{Title: "t\n2", Message: "m"})
	if q.Title != "t 2" || q.YesLabel != "Yes" || q.NoLabel != "No" || q.Timeout != 60*time.Second {
		t.Errorf("defaults: %+v", q)
	}
	q = normalize(Question{YesLabel: "Same", NoLabel: "Same", Timeout: time.Hour})
	if q.YesLabel == q.NoLabel || q.Timeout != maxConfirmTimeout {
		t.Errorf("identical labels / long timeout: %+v", q)
	}
	if s := timeoutSeconds(normalize(Question{Timeout: 1500 * time.Millisecond})); s != 2 {
		t.Errorf("timeoutSeconds = %d, want 2", s)
	}
}

func TestRunTarget(t *testing.T) {
	if got := runTarget(testUser, 0); got != testUser {
		t.Error("root must switch to the user")
	}
	if got := runTarget(testUser, 501); got != nil {
		t.Error("an agent that already is the user must not switch")
	}
	if got := runTarget(testUser, 502); got != testUser {
		t.Error("another unprivileged user must still go through run-as-user")
	}
}

// ---- macOS ----

func newTestMac(rec *recorder, user *platform.User) *macUI {
	m := newMacUI(&platform.Fake{User: user, RunFunc: rec.run, IgnoreAsUser: false})
	m.euid = func() int { return 0 }
	m.timings = fastTimings()
	return m
}

func checkOsascript(t *testing.T, cmd platform.Command, script string, values ...string) {
	t.Helper()
	if cmd.Path != "/usr/bin/osascript" {
		t.Errorf("path = %q", cmd.Path)
	}
	if cmd.AsUser == nil || cmd.AsUser.UID != "501" {
		t.Errorf("must run in the console user's session, AsUser = %+v", cmd.AsUser)
	}
	want := append([]string{"-e", script, "--"}, values...)
	if len(cmd.Args) != len(want) {
		t.Fatalf("argv has %d elements, want %d: %q", len(cmd.Args), len(want), cmd.Args)
	}
	for i := range want {
		if cmd.Args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, cmd.Args[i], want[i])
		}
	}
	// The AppleScript source is the constant: no caller text inside it.
	for _, fragment := range []string{"Jane", "touch", "second line"} {
		if strings.Contains(cmd.Args[1], fragment) {
			t.Errorf("script source contains caller text %q", fragment)
		}
	}
}

func TestMacNotifyPassesTextAsArguments(t *testing.T) {
	rec := &recorder{}
	m := newTestMac(rec, testUser)
	if err := m.Notify(context.Background(), nasty, nasty); err != nil {
		t.Fatal(err)
	}
	cmds := rec.all()
	if len(cmds) != 1 {
		t.Fatalf("commands = %d", len(cmds))
	}
	checkOsascript(t, cmds[0], macNotifyScript, nastyLine, nasty)
}

func TestMacConfirm(t *testing.T) {
	for _, c := range []struct {
		stdout     string
		code       int
		defaultYes bool
		yes, asked bool
		wantErr    bool
	}{
		{"yes\n", 0, false, true, true, false},
		{"no\n", 0, false, false, true, false},
		{"timeout\n", 0, false, false, true, false},
		{"timeout\n", 0, true, true, true, false},
		{"", 1, false, false, false, true},
		{"garbage", 0, false, false, false, true},
	} {
		rec := &recorder{reply: func(_ int, cmd platform.Command, _ context.Context) (int, error) {
			_, _ = cmd.Stdout.Write([]byte(c.stdout))
			return c.code, nil
		}}
		m := newTestMac(rec, testUser)
		yes, asked, err := m.Confirm(context.Background(), Question{
			Title: nasty, Message: nasty, YesLabel: "Allow", NoLabel: "Deny", Timeout: 45 * time.Second, DefaultYes: c.defaultYes,
		})
		if yes != c.yes || asked != c.asked || (err != nil) != c.wantErr {
			t.Errorf("%q/%d: yes=%v asked=%v err=%v", c.stdout, c.code, yes, asked, err)
		}
		def := "Deny"
		if c.defaultYes {
			def = "Allow"
		}
		checkOsascript(t, rec.all()[0], macConfirmScript, nastyLine, nasty, "Allow", "Deny", def, "45")
	}
}

func TestMacNobodyLoggedIn(t *testing.T) {
	rec := &recorder{}
	m := newTestMac(rec, nil)
	if err := m.Notify(context.Background(), "t", "m"); err != nil {
		t.Errorf("Notify: %v", err)
	}
	yes, asked, err := m.Confirm(context.Background(), Question{Title: "t", Message: "m"})
	if yes || asked || err != nil {
		t.Errorf("Confirm: yes=%v asked=%v err=%v", yes, asked, err)
	}
	stop, ended, shown, err := m.ShowIndicator(context.Background(), "t", "m")
	if shown || err != nil || stop == nil || ended == nil {
		t.Errorf("ShowIndicator: shown=%v err=%v", shown, err)
	}
	stop()
	if rec.count() != 0 {
		t.Errorf("no helper may be started when nobody is logged in, got %d", rec.count())
	}
}

func TestMacIndicatorLifecycle(t *testing.T) {
	click := make(chan struct{})
	rec := &recorder{reply: func(n int, cmd platform.Command, ctx context.Context) (int, error) {
		_, _ = cmd.Stderr.Write([]byte(macIndicatorReady + "\n"))
		if n == 1 {
			// The first helper is on screen for a while, then dies without
			// the user ending the session.
			time.Sleep(450 * time.Millisecond)
			return 1, nil
		}
		select {
		case <-ctx.Done():
			return platform.ExitCodeUnknown, ctx.Err()
		case <-click:
			_, _ = cmd.Stdout.Write([]byte("ended\n"))
			return 0, nil
		}
	}}
	m := newTestMac(rec, testUser)
	stop, ended, shown, err := m.ShowIndicator(context.Background(), nasty, nasty)
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	defer stop()
	waitFor(t, "the indicator to be shown again", func() bool { return rec.count() >= 2 })
	checkOsascript(t, rec.all()[1], macIndicatorScript, nastyLine, nasty, EndSessionLabel)
	if isClosed(ended) {
		t.Fatal("ended closed without the user ending the session")
	}
	close(click)
	waitFor(t, "ended", func() bool { return isClosed(ended) })
}

func TestMacIndicatorStopKillsHelper(t *testing.T) {
	exited := make(chan struct{})
	rec := &recorder{reply: func(_ int, cmd platform.Command, ctx context.Context) (int, error) {
		_, _ = cmd.Stderr.Write([]byte(macIndicatorReady))
		<-ctx.Done()
		close(exited)
		return platform.ExitCodeUnknown, ctx.Err()
	}}
	m := newTestMac(rec, testUser)
	// The set-up context ending must not take the indicator down.
	ctx, cancel := context.WithCancel(context.Background())
	stop, ended, shown, err := m.ShowIndicator(ctx, "t", "m")
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	cancel()
	time.Sleep(30 * time.Millisecond)
	if isClosed(exited) {
		t.Fatal("the indicator must live until stop is called")
	}
	stop()
	if !isClosed(exited) {
		t.Fatal("stop must end the helper process before returning")
	}
	if isClosed(ended) {
		t.Error("stop is not the user ending the session")
	}
	stop() // idempotent
}

func TestIndicatorThatCannotBeShown(t *testing.T) {
	// The helper fails at once: ShowIndicator must say so instead of
	// claiming an indicator is on screen.
	rec := &recorder{reply: func(int, platform.Command, context.Context) (int, error) { return 1, nil }}
	m := newTestMac(rec, testUser)
	_, _, shown, err := m.ShowIndicator(context.Background(), "t", "m")
	if shown || err == nil {
		t.Fatalf("shown=%v err=%v", shown, err)
	}

	// The helper works first and then keeps failing while the user is still
	// logged in: the session must not go on without an indicator.
	var mu sync.Mutex
	failing := false
	rec = &recorder{reply: func(_ int, cmd platform.Command, ctx context.Context) (int, error) {
		mu.Lock()
		f := failing
		mu.Unlock()
		if f {
			return 1, nil
		}
		_, _ = cmd.Stderr.Write([]byte(macIndicatorReady))
		<-ctx.Done()
		return platform.ExitCodeUnknown, ctx.Err()
	}}
	m = newTestMac(rec, testUser)
	gone := make(chan struct{})
	fake := m.plat.(*platform.Fake)
	inner := fake.RunFunc
	fake.RunFunc = func(ctx context.Context, cmd platform.Command) (int, error) {
		mu.Lock()
		f := failing
		mu.Unlock()
		if f {
			return inner(ctx, cmd)
		}
		// Simulate the helper being killed from outside.
		hctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-gone:
				mu.Lock()
				failing = true
				mu.Unlock()
				cancel()
			case <-hctx.Done():
			}
		}()
		code, err := inner(hctx, cmd)
		cancel()
		if ctx.Err() == nil {
			return 1, nil
		}
		return code, err
	}
	stop, ended, shown, err := m.ShowIndicator(context.Background(), "t", "m")
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	defer stop()
	close(gone)
	waitFor(t, "ended after the indicator was lost", func() bool { return isClosed(ended) })
}

// seatPlatform is a Platform whose console user can change during a test.
type seatPlatform struct {
	platform.Fake
	mu   sync.Mutex
	user *platform.User
}

func (s *seatPlatform) set(u *platform.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.user = u
}

func (s *seatPlatform) ConsoleUser(context.Context) (*platform.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil {
		return nil, platform.ErrNoConsoleUser
	}
	u := *s.user
	return &u, nil
}

func TestIndicatorWaitsForNextUserAfterLogout(t *testing.T) {
	fake := &seatPlatform{user: testUser}
	var mu sync.Mutex
	shownTo := []string{}
	logout := make(chan struct{})
	tm := fastTimings()
	stop, ended, shown, err := runIndicator(context.Background(), fake, tm, func(ctx context.Context, u *platform.User, ready func()) (showResult, error) {
		mu.Lock()
		shownTo = append(shownTo, u.Name)
		n := len(shownTo)
		mu.Unlock()
		ready()
		if n == 1 {
			<-logout
			return showClosed, errors.New("helper died with the user's session")
		}
		<-ctx.Done()
		return showClosed, ctx.Err()
	})
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	defer stop()
	// Log the user out, then let somebody else log in.
	fake.set(nil)
	close(logout)
	time.Sleep(50 * time.Millisecond)
	if isClosed(ended) {
		t.Fatal("a logout is not a reason to end the session")
	}
	fake.set(&platform.User{Name: "bob", UID: "502"})
	waitFor(t, "the indicator for the next user", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(shownTo) == 2 && shownTo[1] == "bob"
	})
}

// ---- Linux ----

const (
	loginctlList = `     2 1000 alice seat0 tty2
     5 1000 alice       pts/3
    c1  120 gdm   seat0 tty1
`
	loginctlGraphical = "Id=2\nName=alice\nType=x11\nDisplay=:1\nTTY=tty2\nState=active\nClass=user\nActive=yes\nRemote=no\n"
	loginctlSSH       = "Id=5\nName=alice\nType=tty\nDisplay=\nTTY=pts/3\nState=active\nClass=user\nActive=yes\nRemote=yes\n"
	loginctlGreeter   = "Id=c1\nName=gdm\nType=wayland\nDisplay=\nTTY=tty1\nState=online\nClass=greeter\nActive=no\nRemote=no\n"
	loginctlText      = "Id=2\nName=alice\nType=tty\nDisplay=\nTTY=tty2\nState=active\nClass=user\nActive=yes\nRemote=no\n"
)

var linuxUser = &platform.User{Name: "alice", UID: "1000", GID: "1000", Home: "/home/alice"}

type linuxFixture struct {
	rec      *recorder
	ui       *linuxUI
	mu       sync.Mutex
	tty      map[string]string
	tools    map[string]bool
	graphics bool
	helper   func(n int, cmd platform.Command, ctx context.Context) (int, error)
}

func newLinuxFixture(t *testing.T, graphical bool, tools ...string) *linuxFixture {
	t.Helper()
	fx := &linuxFixture{tty: map[string]string{}, tools: map[string]bool{"loginctl": true}, graphics: graphical}
	for _, tool := range tools {
		fx.tools[tool] = true
	}
	fx.rec = &recorder{reply: func(n int, cmd platform.Command, ctx context.Context) (int, error) {
		if filepath.Base(cmd.Path) == "loginctl" {
			out := ""
			switch {
			case cmd.Args[0] == "list-sessions":
				out = loginctlList
			case cmd.Args[1] == "2" && fx.graphics:
				out = loginctlGraphical
			case cmd.Args[1] == "2":
				out = loginctlText
			case cmd.Args[1] == "5":
				out = loginctlSSH
			case cmd.Args[1] == "c1":
				out = loginctlGreeter
			}
			_, _ = cmd.Stdout.Write([]byte(out))
			return 0, nil
		}
		if fx.helper != nil {
			return fx.helper(n, cmd, ctx)
		}
		return 0, nil
	}}
	ui := newLinuxUI(&platform.Fake{User: linuxUser, RunFunc: fx.rec.run})
	ui.euid = func() int { return 0 }
	ui.timings = fastTimings()
	ui.ttyPoll = 5 * time.Millisecond
	ui.ttyReminder = time.Hour
	ui.look = func(name string) (string, error) {
		if fx.tools[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	ui.procEnv = func(uid string) map[string]string {
		if uid != "1000" {
			t.Errorf("procEnv uid = %q", uid)
		}
		return map[string]string{"XAUTHORITY": "/run/user/1000/gdm/Xauthority", "DISPLAY": ":1", "SECRET_TOKEN": "do-not-pass-on", "DBUS_SESSION_BUS_ADDRESS": "bad\nvalue"}
	}
	ui.writeTTY = func(path, text string) error {
		fx.mu.Lock()
		defer fx.mu.Unlock()
		fx.tty[path] += text
		return nil
	}
	fx.ui = ui
	return fx
}

func (fx *linuxFixture) helpers() []platform.Command {
	var out []platform.Command
	for _, c := range fx.rec.all() {
		if filepath.Base(c.Path) != "loginctl" {
			out = append(out, c)
		}
	}
	return out
}

func (fx *linuxFixture) ttyText(path string) string {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return fx.tty[path]
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestLinuxParseAndPickDesktop(t *testing.T) {
	ids := parseSessionIDs(loginctlList + "\n$(bad) x\n")
	if strings.Join(ids, ",") != "2,5,c1" {
		t.Errorf("ids = %v", ids)
	}
	sessions := []loginSession{parseLoginSession(loginctlGraphical), parseLoginSession(loginctlSSH), parseLoginSession(loginctlGreeter)}
	d := pickDesktop(linuxUser, sessions, map[string]string{"XAUTHORITY": "/home/alice/.Xauthority", "DISPLAY": ":1; rm -rf /"})
	if !d.Graphical {
		t.Fatal("graphical session not detected")
	}
	env := strings.Join(d.Env, "\n")
	for _, want := range []string{"DISPLAY=:1", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "XAUTHORITY=/home/alice/.Xauthority"} {
		if !hasArg(d.Env, want) {
			t.Errorf("env lacks %q:\n%s", want, env)
		}
	}
	if strings.Contains(env, "rm -rf") {
		t.Errorf("an implausible DISPLAY was passed on:\n%s", env)
	}
	if len(d.TTYs) != 1 || d.TTYs[0] != "/dev/pts/3" {
		t.Errorf("ttys = %v", d.TTYs)
	}

	wl := parseLoginSession("Name=alice\nType=wayland\nState=active\nClass=user\nActive=yes\n")
	d = pickDesktop(linuxUser, []loginSession{wl}, nil)
	if !hasArg(d.Env, "WAYLAND_DISPLAY=wayland-0") {
		t.Errorf("wayland env = %v", d.Env)
	}

	d = pickDesktop(linuxUser, []loginSession{parseLoginSession(loginctlText), parseLoginSession("Name=alice\nType=tty\nTTY=../../etc/passwd\nClass=user\n")}, nil)
	if d.Graphical || len(d.TTYs) != 1 || d.TTYs[0] != "/dev/tty2" {
		t.Errorf("text login: %+v", d)
	}
	// Other users' sessions (the greeter) never count.
	if d := pickDesktop(linuxUser, []loginSession{parseLoginSession(loginctlGreeter)}, nil); d.Graphical || len(d.TTYs) != 0 {
		t.Errorf("greeter session used: %+v", d)
	}
}

func TestLinuxConfirmZenity(t *testing.T) {
	for _, c := range []struct {
		code       int
		stderr     string
		defaultYes bool
		yes, asked bool
		wantErr    bool
	}{
		{0, "", false, true, true, false},
		{1, "", false, false, true, false},
		{5, "", false, false, true, false},
		{5, "", true, true, true, false},
		{1, "(zenity:1): Gtk-WARNING **: cannot open display: :1", false, false, false, true},
		{255, "", false, false, false, true},
	} {
		fx := newLinuxFixture(t, true, "zenity", "kdialog")
		fx.helper = func(_ int, cmd platform.Command, _ context.Context) (int, error) {
			_, _ = cmd.Stderr.Write([]byte(c.stderr))
			return c.code, nil
		}
		yes, asked, err := fx.ui.Confirm(context.Background(), Question{
			Title: nasty, Message: nasty, YesLabel: "Allow", NoLabel: "Deny", Timeout: 30 * time.Second, DefaultYes: c.defaultYes,
		})
		if yes != c.yes || asked != c.asked || (err != nil) != c.wantErr {
			t.Errorf("exit %d: yes=%v asked=%v err=%v", c.code, yes, asked, err)
		}
		h := fx.helpers()
		if len(h) != 1 {
			t.Fatalf("helpers = %d", len(h))
		}
		cmd := h[0]
		if cmd.Path != "/usr/bin/zenity" || cmd.AsUser == nil || cmd.AsUser.Name != "alice" {
			t.Errorf("command = %q as %+v", cmd.Path, cmd.AsUser)
		}
		// Each text is one argv element, attached to its option.
		for _, want := range []string{"--question", "--title=" + nastyLine, "--text=" + nasty, "--ok-label=Allow", "--cancel-label=Deny", "--timeout=30", "--no-markup"} {
			if !hasArg(cmd.Args, want) {
				t.Errorf("argv lacks %q: %q", want, cmd.Args)
			}
		}
		if hasArg(cmd.Args, "--default-cancel") == c.defaultYes {
			t.Errorf("--default-cancel wrong for DefaultYes=%v", c.defaultYes)
		}
		for _, want := range []string{"DISPLAY=:1", "XAUTHORITY=/run/user/1000/gdm/Xauthority", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"} {
			if !hasArg(cmd.Env, want) {
				t.Errorf("env lacks %q: %q", want, cmd.Env)
			}
		}
		for _, kv := range cmd.Env {
			if strings.Contains(kv, "SECRET") || strings.Contains(kv, "bad") {
				t.Errorf("unexpected variable passed on: %q", kv)
			}
		}
	}
}

func TestLinuxConfirmKdialogAndTimeout(t *testing.T) {
	fx := newLinuxFixture(t, true, "kdialog")
	fx.helper = func(_ int, _ platform.Command, ctx context.Context) (int, error) {
		<-ctx.Done() // nobody answers
		return platform.ExitCodeUnknown, ctx.Err()
	}
	started := time.Now()
	yes, asked, err := fx.ui.Confirm(context.Background(), Question{Title: "t", Message: nasty, Timeout: time.Second})
	if yes || !asked || err != nil {
		t.Errorf("timeout: yes=%v asked=%v err=%v", yes, asked, err)
	}
	if d := time.Since(started); d < 900*time.Millisecond || d > 5*time.Second {
		t.Errorf("returned after %v", d)
	}
	cmd := fx.helpers()[0]
	if cmd.Path != "/usr/bin/kdialog" || !hasArg(cmd.Args, "--yesno="+nasty) || !hasArg(cmd.Args, "--yes-label=Yes") {
		t.Errorf("kdialog argv = %q", cmd.Args)
	}
}

func TestLinuxTextLoginAndHeadless(t *testing.T) {
	// Text-only login: no prompt possible, notices go to the terminals.
	fx := newLinuxFixture(t, false, "zenity", "notify-send")
	yes, asked, err := fx.ui.Confirm(context.Background(), Question{Title: "t", Message: "m"})
	if yes || asked || err != nil {
		t.Errorf("Confirm on a text login: yes=%v asked=%v err=%v", yes, asked, err)
	}
	if err := fx.ui.Notify(context.Background(), "Remote support", nasty); err != nil {
		t.Fatal(err)
	}
	if len(fx.helpers()) != 0 {
		t.Errorf("no GUI helper may run for a text login: %d", len(fx.helpers()))
	}
	for _, tty := range []string{"/dev/tty2", "/dev/pts/3"} {
		if got := fx.ttyText(tty); !strings.Contains(got, "DranzoRMM: Remote support") || !strings.Contains(got, "second line") {
			t.Errorf("%s got %q", tty, got)
		}
	}

	// Headless: nobody logged in.
	fx = newLinuxFixture(t, true, "zenity")
	fx.ui.plat.(*platform.Fake).User = nil
	if err := fx.ui.Notify(context.Background(), "t", "m"); err != nil {
		t.Errorf("Notify: %v", err)
	}
	yes, asked, err = fx.ui.Confirm(context.Background(), Question{Title: "t", Message: "m"})
	if yes || asked || err != nil {
		t.Errorf("Confirm: yes=%v asked=%v err=%v", yes, asked, err)
	}
	stop, _, shown, err := fx.ui.ShowIndicator(context.Background(), "t", "m")
	stop()
	if shown || err != nil {
		t.Errorf("ShowIndicator: shown=%v err=%v", shown, err)
	}
	if fx.rec.count() != 0 {
		t.Errorf("commands run with nobody logged in: %d", fx.rec.count())
	}
}

func TestLinuxNotifySend(t *testing.T) {
	fx := newLinuxFixture(t, true, "notify-send", "zenity")
	if err := fx.ui.Notify(context.Background(), "-t 1 --hint=x", "<a href=\"http://x\">click</a> "+nasty); err != nil {
		t.Fatal(err)
	}
	cmd := fx.helpers()[0]
	if cmd.Path != "/usr/bin/notify-send" {
		t.Fatalf("path = %q", cmd.Path)
	}
	n := len(cmd.Args)
	// Title and body come after "--": a title that looks like an option is data.
	if n < 3 || cmd.Args[n-3] != "--" || cmd.Args[n-2] != "-t 1 --hint=x" {
		t.Errorf("argv = %q", cmd.Args)
	}
	if strings.ContainsAny(cmd.Args[n-1], "<>") || !strings.Contains(cmd.Args[n-1], "$(touch /tmp/pwned)") {
		t.Errorf("body = %q", cmd.Args[n-1])
	}
}

func TestLinuxIndicatorZenity(t *testing.T) {
	fx := newLinuxFixture(t, true, "zenity")
	click := make(chan struct{})
	fx.helper = func(n int, _ platform.Command, ctx context.Context) (int, error) {
		select {
		case <-ctx.Done():
			return platform.ExitCodeUnknown, ctx.Err()
		case <-click:
			return 0, nil
		case <-time.After(60 * time.Millisecond):
			return 1, nil // the user closed the window
		}
	}
	stop, ended, shown, err := fx.ui.ShowIndicator(context.Background(), "Remote session active", nasty)
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	defer stop()
	waitFor(t, "the closed indicator to come back", func() bool { return len(fx.helpers()) >= 3 })
	if isClosed(ended) {
		t.Fatal("closing the window must not end the session")
	}
	cmd := fx.helpers()[0]
	for _, want := range []string{"--info", "--title=Remote session active", "--text=" + nasty, "--ok-label=" + EndSessionLabel, "--no-markup"} {
		if !hasArg(cmd.Args, want) {
			t.Errorf("argv lacks %q: %q", want, cmd.Args)
		}
	}
	close(click)
	waitFor(t, "ended", func() bool { return isClosed(ended) })
}

func TestLinuxIndicatorOnTextTerminal(t *testing.T) {
	fx := newLinuxFixture(t, false)
	dir := t.TempDir()
	endPath := filepath.Join(dir, endFilePrefix+"test")
	fx.ui.endFile = func(u *platform.User) string {
		if err := os.WriteFile(endPath, nil, 0o600); err != nil {
			t.Error(err)
		}
		return endPath
	}
	stop, ended, shown, err := fx.ui.ShowIndicator(context.Background(), "Remote session active", "Remote session active: Jane Doe (Example IT)")
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	got := fx.ttyText("/dev/tty2")
	if !strings.Contains(got, "Remote session active: Jane Doe (Example IT)") || !strings.Contains(got, "rm "+endPath) {
		t.Errorf("start notice = %q", got)
	}
	if isClosed(ended) {
		t.Fatal("ended too early")
	}
	// The user ends the session locally.
	if err := os.Remove(endPath); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "ended", func() bool { return isClosed(ended) })
	stop()

	// stop announces the end and removes the file.
	fx = newLinuxFixture(t, false)
	fx.ui.endFile = func(*platform.User) string {
		_ = os.WriteFile(endPath, nil, 0o600)
		return endPath
	}
	stop, _, shown, err = fx.ui.ShowIndicator(context.Background(), "t", "m")
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	stop()
	if got := fx.ttyText("/dev/tty2"); !strings.Contains(got, "The remote session has ended.") {
		t.Errorf("end notice missing: %q", got)
	}
	if _, err := os.Lstat(endPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("end file left behind: %v", err)
	}
}

func TestLinuxDesktopWithoutDialogTool(t *testing.T) {
	// A desktop session without zenity / kdialog and without a terminal:
	// there is no way to prompt or to show an indicator.
	fx := newLinuxFixture(t, true)
	fx.rec.reply = func(_ int, cmd platform.Command, _ context.Context) (int, error) {
		if cmd.Args[0] == "list-sessions" {
			_, _ = cmd.Stdout.Write([]byte("2 1000 alice seat0 tty2\n"))
		} else {
			_, _ = cmd.Stdout.Write([]byte(strings.Replace(loginctlGraphical, "TTY=tty2", "TTY=", 1)))
		}
		return 0, nil
	}
	yes, asked, err := fx.ui.Confirm(context.Background(), Question{Title: "t", Message: "m"})
	if yes || asked || err != nil {
		t.Errorf("Confirm: yes=%v asked=%v err=%v", yes, asked, err)
	}
	_, _, shown, err := fx.ui.ShowIndicator(context.Background(), "t", "m")
	if shown || err == nil {
		t.Errorf("ShowIndicator: shown=%v err=%v (want an error: a user is logged in but cannot be shown anything)", shown, err)
	}
}

// ---- Windows ----

type fakeMessageBox struct {
	mu       sync.Mutex
	calls    []fakeMessage
	response uint32
	err      error
	block    chan struct{}
}

type fakeMessage struct {
	session        uint32
	title, text    string
	style, timeout uint32
	wait           bool
}

func (f *fakeMessageBox) Send(sessionID uint32, title, text string, style, timeoutSeconds uint32, wait bool) (uint32, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeMessage{sessionID, title, text, style, timeoutSeconds, wait})
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	return f.response, f.err
}

func newTestWin(rec *recorder, mb *fakeMessageBox, user *platform.User) *winUI {
	w := newWinUI(&platform.Fake{User: user, RunFunc: rec.run}, mb)
	w.ps = func() string { return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` }
	w.pid = 4242
	w.timings = fastTimings()
	w.timings.presumeReady = 0
	return w
}

func TestWindowsNotifyAndConfirm(t *testing.T) {
	mb := &fakeMessageBox{response: idYes}
	w := newTestWin(&recorder{}, mb, testUser)
	if err := w.Notify(context.Background(), nasty, nasty); err != nil {
		t.Fatal(err)
	}
	n := mb.calls[0]
	if n.session != 3 || n.wait || n.title != nastyLine || n.text != nasty || n.style&mbYesNo != 0 || n.timeout == 0 {
		t.Errorf("notify call = %+v", n)
	}

	for _, c := range []struct {
		response   uint32
		defaultYes bool
		yes, asked bool
		wantErr    bool
	}{
		{idYes, false, true, true, false},
		{idNo, false, false, true, false},
		{idTimeout, false, false, true, false},
		{idTimeout, true, true, true, false},
		{1, false, false, false, true},
	} {
		mb := &fakeMessageBox{response: c.response}
		w := newTestWin(&recorder{}, mb, testUser)
		yes, asked, err := w.Confirm(context.Background(), Question{
			Title: "Remote support", Message: nasty, YesLabel: "Allow", NoLabel: "Deny", Timeout: 90 * time.Second, DefaultYes: c.defaultYes,
		})
		if yes != c.yes || asked != c.asked || (err != nil) != c.wantErr {
			t.Errorf("response %d: yes=%v asked=%v err=%v", c.response, yes, asked, err)
		}
		call := mb.calls[0]
		if call.session != 3 || !call.wait || call.timeout != 90 || call.style&mbYesNo == 0 {
			t.Errorf("confirm call = %+v", call)
		}
		if (call.style&mbDefButton2 != 0) == c.defaultYes {
			t.Errorf("default button wrong for DefaultYes=%v", c.defaultYes)
		}
		if !strings.HasPrefix(call.text, nasty) || !strings.Contains(call.text, "Yes = Allow") || !strings.Contains(call.text, "No = Deny") {
			t.Errorf("text = %q", call.text)
		}
	}

	mb = &fakeMessageBox{err: errors.New("access denied")}
	w = newTestWin(&recorder{}, mb, testUser)
	if _, asked, err := w.Confirm(context.Background(), Question{Title: "t", Message: "m"}); asked || err == nil {
		t.Errorf("failed prompt: asked=%v err=%v", asked, err)
	}

	// Nobody logged in.
	mb = &fakeMessageBox{}
	rec := &recorder{}
	w = newTestWin(rec, mb, nil)
	_ = w.Notify(context.Background(), "t", "m")
	yes, asked, err := w.Confirm(context.Background(), Question{Title: "t", Message: "m"})
	stop, _, shown, ierr := w.ShowIndicator(context.Background(), "t", "m")
	stop()
	if yes || asked || err != nil || shown || ierr != nil || len(mb.calls) != 0 || rec.count() != 0 {
		t.Errorf("nobody logged in: yes=%v asked=%v err=%v shown=%v ierr=%v calls=%d cmds=%d", yes, asked, err, shown, ierr, len(mb.calls), rec.count())
	}
}

func TestWindowsConfirmHonoursContext(t *testing.T) {
	mb := &fakeMessageBox{block: make(chan struct{})}
	defer close(mb.block)
	w := newTestWin(&recorder{}, mb, testUser)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	yes, asked, err := w.Confirm(ctx, Question{Title: "t", Message: "m"})
	if yes || asked || err == nil {
		t.Errorf("yes=%v asked=%v err=%v", yes, asked, err)
	}
}

func TestWindowsIndicator(t *testing.T) {
	click := make(chan struct{})
	rec := &recorder{reply: func(_ int, cmd platform.Command, ctx context.Context) (int, error) {
		_, _ = cmd.Stdout.Write([]byte(winIndicatorShown + "\r\n"))
		select {
		case <-ctx.Done():
			return platform.ExitCodeUnknown, ctx.Err()
		case <-click:
			return winIndicatorEnded, nil
		}
	}}
	w := newTestWin(rec, &fakeMessageBox{}, testUser)
	stop, ended, shown, err := w.ShowIndicator(context.Background(), nasty, nasty)
	if err != nil || !shown {
		t.Fatalf("shown=%v err=%v", shown, err)
	}
	defer stop()
	cmd := rec.all()[0]
	if !strings.HasSuffix(cmd.Path, `powershell.exe`) || cmd.AsUser == nil || cmd.AsUser.SessionID != 3 {
		t.Errorf("command = %q as %+v", cmd.Path, cmd.AsUser)
	}
	if got := strings.Join(cmd.Args, " "); got != "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -Command -" {
		t.Errorf("argv = %q", got)
	}
	for _, a := range cmd.Args {
		if strings.Contains(a, "Jane") {
			t.Errorf("caller text on the command line: %q", a)
		}
	}
	for _, want := range []string{EnvTitle + "=" + nastyLine, EnvMessage + "=" + nasty, EnvEndLabel + "=" + EndSessionLabel, EnvParentPID + "=4242"} {
		if !hasArg(cmd.Env, want) {
			t.Errorf("env lacks %q", want)
		}
	}
	// The script is the constant and reads its texts from the environment.
	buf := make([]byte, len(winIndicatorScript)+16)
	n, _ := cmd.Stdin.Read(buf)
	script := string(buf[:n])
	if script != winIndicatorScript {
		t.Error("the script on stdin is not the constant")
	}
	for _, want := range []string{"$env:" + EnvTitle, "$env:" + EnvMessage, "TopMost = $true", "ControlBox = $false", "exit 100"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(script, "Jane") || strings.Contains(script, "touch") {
		t.Error("caller text inside the script")
	}
	for i, line := range strings.Split(strings.TrimSpace(script), "\n") {
		if strings.Count(line, "{") != strings.Count(line, "}") || strings.Count(line, "(") != strings.Count(line, ")") {
			t.Errorf("line %d is not a complete statement (stdin is executed line by line): %s", i+1, line)
		}
	}
	close(click)
	waitFor(t, "ended", func() bool { return isClosed(ended) })
}

func TestWindowsIndicatorMustReportShown(t *testing.T) {
	// PowerShell starts but the window never appears (blocked script host):
	// the indicator must not be reported as shown.
	rec := &recorder{reply: func(int, platform.Command, context.Context) (int, error) { return 1, nil }}
	w := newTestWin(rec, &fakeMessageBox{}, testUser)
	_, _, shown, err := w.ShowIndicator(context.Background(), "t", "m")
	if shown || err == nil {
		t.Errorf("shown=%v err=%v", shown, err)
	}

	rec = &recorder{reply: func(_ int, _ platform.Command, ctx context.Context) (int, error) {
		<-ctx.Done() // hangs without ever printing the marker
		return platform.ExitCodeUnknown, ctx.Err()
	}}
	w = newTestWin(rec, &fakeMessageBox{}, testUser)
	w.timings.startTimeout = 80 * time.Millisecond
	_, _, shown, err = w.ShowIndicator(context.Background(), "t", "m")
	if shown || err == nil {
		t.Errorf("hung helper: shown=%v err=%v", shown, err)
	}
}

func TestFakeKeepsItsContract(t *testing.T) {
	f := NewFake()
	if err := f.Notify(context.Background(), "t", "m"); err != nil {
		t.Fatal(err)
	}
	yes, asked, err := f.Confirm(context.Background(), Question{Title: "q"})
	if !yes || !asked || err != nil {
		t.Errorf("Confirm: %v %v %v", yes, asked, err)
	}
	stop, ended, shown, err := f.ShowIndicator(context.Background(), "t", "m")
	if !shown || err != nil || isClosed(ended) {
		t.Fatalf("ShowIndicator: %v %v", shown, err)
	}
	f.UserEndsSession()
	if !isClosed(ended) {
		t.Error("UserEndsSession must close ended")
	}
	stop()
	n, q, i, stopped := f.Snapshot()
	if len(n) != 1 || len(q) != 1 || len(i) != 1 || stopped != 1 {
		t.Errorf("snapshot: %v %v %v %d", n, q, i, stopped)
	}

	f.Set(func(f *Fake) { f.TimesOut = true })
	started := time.Now()
	yes, asked, err = f.Confirm(context.Background(), Question{Timeout: 50 * time.Millisecond, DefaultYes: false})
	if yes || !asked || err != nil || time.Since(started) < 50*time.Millisecond {
		t.Errorf("timeout: %v %v %v after %v", yes, asked, err, time.Since(started))
	}
}

// The macOS consent question is announced in Notification Center (with a
// sound) before the dialog, so a dialog hidden behind a full-screen app or on
// another Space is still noticed. The announcement uses the argv variables,
// never inlined text, and is best effort (inside try).
func TestMacConfirmAnnouncesBeforeTheDialog(t *testing.T) {
	n := strings.Index(macConfirmScript, "display notification dlgText with title dlgTitle")
	d := strings.Index(macConfirmScript, "display dialog dlgText")
	if n < 0 || d < 0 || n > d {
		t.Fatalf("notification must come before the dialog (notification at %d, dialog at %d)", n, d)
	}
	if !strings.Contains(macConfirmScript[:n], "try") {
		t.Fatal("the notification must be inside try so a refusal cannot stop the dialog")
	}
}
