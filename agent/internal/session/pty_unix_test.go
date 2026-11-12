//go:build !windows

package session

import (
	"context"
	"errors"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// These tests start a real shell on a real pseudo-terminal.

type realFixture struct {
	t    *testing.T
	h    *Handler
	send *fakeSender
	ui   *userui.Fake
	ctx  context.Context
	id   string
}

func newRealFixture(t *testing.T, plat platform.Platform) *realFixture {
	t.Helper()
	fx := &realFixture{t: t, send: newSender(), ui: userui.NewFake()}
	fx.h = New(agentcore.Env{Sender: fx.send, Seq: protocol.NewSeqTracker(), Platform: plat, Log: logging.Discard()}, fx.ui, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	fx.ctx = ctx
	t.Cleanup(func() {
		cancel()
		fx.h.ConnectionLost()
	})
	return fx
}

func (fx *realFixture) start(runAs string) {
	fx.t.Helper()
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	msg.Terminal = &protocol.TerminalOptions{Cols: 100, Rows: 40, RunAs: runAs}
	fx.id = msg.SessionID
	fx.h.Start(fx.ctx, msg)
	fx.send.await(fx.t, "active or failed", func() bool {
		for _, s := range fx.send.statuses(fx.id) {
			if s.State == protocol.SessionActive {
				return true
			}
			if s.State == protocol.SessionFailed {
				fx.t.Fatalf("session failed: %s", s.Reason)
			}
		}
		return false
	})
}

func (fx *realFixture) typeLine(line string) {
	fx.h.Input(fx.ctx, input(fx.id, line+"\n"))
}

func (fx *realFixture) text() string { return string(fx.send.output(fx.t, fx.id)) }

// expect waits until the terminal output matches re and returns the first
// submatch (or the whole match).
func (fx *realFixture) expect(re string) string {
	fx.t.Helper()
	rx := regexp.MustCompile(re)
	var m []string
	deadline := time.Now().Add(wait)
	for {
		if m = rx.FindStringSubmatch(fx.text()); m != nil {
			break
		}
		if time.Now().After(deadline) {
			fx.t.Fatalf("terminal output never matched %q; output so far:\n%q", re, fx.text())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(m) > 1 {
		return m[1]
	}
	return m[0]
}

// alive reports whether pid is a running process. A zombie (killed, but not
// yet reaped by its parent - in a container PID 1 often never reaps) is dead.
func alive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	if data, rerr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); rerr == nil {
		if i := strings.LastIndexByte(string(data), ')'); i >= 0 {
			if f := strings.Fields(string(data)[i+1:]); len(f) > 0 && f[0] == "Z" {
				return false
			}
		}
	}
	return true
}

func waitDead(t *testing.T, what string, pid int) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still running after the session ended", what, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil || n <= 1 {
		t.Fatalf("not a pid: %q", s)
	}
	return n
}

func TestRealTerminalEchoResizeExit(t *testing.T) {
	fx := newRealFixture(t, &platform.Fake{})
	fx.start(protocol.RunAsSystem)

	// The arithmetic proves a shell evaluated the line: the typed text only
	// contains "$((6*7))", never "dz-42".
	fx.typeLine("echo dz-$((6*7))")
	fx.expect(`dz-42`)

	// Initial size, then a resize.
	fx.typeLine("echo size=$(stty size | tr ' ' x)")
	fx.expect(`size=40x100`)
	fx.h.Input(fx.ctx, protocol.SessionInput{SessionID: fx.id, Kind: protocol.SessionInputResize, Cols: 132, Rows: 43})
	fx.typeLine("echo resized=$(stty size | tr ' ' x)")
	fx.expect(`resized=43x132`)

	fx.typeLine("echo term=$TERM tty=$(tty)")
	fx.expect(`term=xterm-256color tty=/dev/`)

	fx.typeLine("echo shellpid=$$=")
	shellPID := atoi(t, fx.expect(`shellpid=(\d+)=`))
	if !alive(shellPID) {
		t.Fatalf("shell pid %d is not running", shellPID)
	}

	fx.typeLine("exit")
	st := fx.send.awaitState(t, fx.id, protocol.SessionEnded)
	if st.Reason != ReasonTerminalExited {
		t.Errorf("reason = %q", st.Reason)
	}
	waitDead(t, "shell", shellPID)
	if _, ok := fx.h.ActiveSession(fx.id); ok {
		t.Error("session still active")
	}
	if _, _, _, stopped := fx.ui.Snapshot(); stopped != 1 {
		t.Errorf("indicator stopped %d times", stopped)
	}
}

// startBusyShell starts a terminal with a background job, a job that ignores
// SIGHUP and a foreground command, and returns their pids.
func startBusyShell(t *testing.T, fx *realFixture) (shell, background, stubborn int) {
	t.Helper()
	fx.typeLine("echo shellpid=$$=")
	shell = atoi(t, fx.expect(`shellpid=(\d+)=`))
	fx.typeLine("sleep 600 & echo bgpid=$!=")
	background = atoi(t, fx.expect(`bgpid=(\d+)=`))
	fx.typeLine("(trap '' HUP INT TERM; exec sleep 601) & echo nohuppid=$!=")
	stubborn = atoi(t, fx.expect(`nohuppid=(\d+)=`))
	// A foreground command keeps the shell busy when the session ends.
	fx.typeLine("echo fg-start; sleep 602")
	fx.expect(`fg-start\r?\n`)
	for _, pid := range []int{shell, background, stubborn} {
		if !alive(pid) {
			t.Fatalf("pid %d is not running", pid)
		}
	}
	return shell, background, stubborn
}

func TestRealTerminalNothingSurvivesTheSession(t *testing.T) {
	for name, end := range map[string]func(fx *realFixture) string{
		"session.end": func(fx *realFixture) string {
			fx.h.End(fx.ctx, protocol.SessionEnd{SessionID: fx.id})
			return fx.send.awaitState(fx.t, fx.id, protocol.SessionEnded).Reason
		},
		"end session on the device": func(fx *realFixture) string {
			fx.ui.UserEndsSession()
			return fx.send.awaitState(fx.t, fx.id, protocol.SessionEnded).Reason
		},
		"connection lost": func(fx *realFixture) string {
			fx.send.block(true)
			fx.h.ConnectionLost()
			return ReasonConnectionLost
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newRealFixture(t, &platform.Fake{})
			fx.start(protocol.RunAsSystem)
			shell, background, stubborn := startBusyShell(t, fx)
			reason := end(fx)
			switch name {
			case "session.end":
				if reason != ReasonEndedByServer {
					t.Errorf("reason = %q", reason)
				}
			case "end session on the device":
				if reason != ReasonEndedLocally {
					t.Errorf("reason = %q", reason)
				}
			}
			// The shell and everything started from it are gone, including
			// the job that ignores SIGHUP.
			waitDead(t, "shell", shell)
			waitDead(t, "background job", background)
			waitDead(t, "job that ignores SIGHUP", stubborn)
			if _, ok := fx.h.ActiveSession(fx.id); ok {
				t.Error("session still active")
			}
		})
	}
}

// TestRealTerminalAsUser needs root and a test account: it is run in the
// Linux containers with DRANZO_TEST_USER set (see the package README note in
// the test output when skipped).
func TestRealTerminalAsUser(t *testing.T) {
	name := os.Getenv("DRANZO_TEST_USER")
	if name == "" || os.Geteuid() != 0 {
		t.Skip("needs root and DRANZO_TEST_USER (run in a container)")
	}
	lu, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	account := &platform.User{Name: lu.Username, UID: lu.Uid, GID: lu.Gid, Home: lu.HomeDir}
	for _, mode := range asUserModes() {
		t.Run(mode.name, func(t *testing.T) {
			defer mode.setup()()
			fx := newRealFixture(t, &platform.Fake{User: account})
			fx.start(protocol.RunAsUser)

			// The quotes keep the terminal's echo of the typed line from
			// matching: only the shell's output contains "who=<name>=".
			fx.typeLine(`echo who""=$(id -un)= uid""=$(id -u)= home""=$HOME= pwd""=$(pwd)=`)
			if got := fx.expect(`who=([^=\r\n]+)=`); got != name {
				t.Fatalf("shell runs as %q, want %q", got, name)
			}
			if got := fx.expect(`uid=(\d+)=`); got != lu.Uid {
				t.Errorf("uid = %s, want %s", got, lu.Uid)
			}
			if got := fx.expect(`home=([^=\r\n]+)=`); got != lu.HomeDir {
				t.Errorf("HOME = %s, want %s", got, lu.HomeDir)
			}
			if got := fx.expect(`pwd=([^=\r\n]+)=`); got != lu.HomeDir {
				t.Errorf("working directory = %s, want %s", got, lu.HomeDir)
			}
			// The shell is not root in any way: no root group, cannot read
			// root-only files, and it owns its terminal.
			fx.typeLine(`echo groups""=$(id -G | tr ' ' ,)= shadow""=$(cat /etc/shadow >/dev/null 2>&1 && echo readable || echo denied)= ttyowner""=$(stat -c %U $(tty))=`)
			if groups := fx.expect(`groups=([0-9,]+)=`); groups == "" || strings.Contains(","+groups+",", ",0,") {
				t.Errorf("groups = %q", groups)
			}
			if got := fx.expect(`shadow=(\w+)=`); got != "denied" {
				t.Errorf("the user shell can read /etc/shadow")
			}
			if got := fx.expect(`ttyowner=([^=\r\n]+)=`); got != name {
				t.Errorf("terminal device owned by %q", got)
			}
			// Job control works (the shell has a controlling terminal).
			fx.typeLine(`sleep 600 & echo bgpid=$!=; echo jobs""=$(jobs | grep -c sleep)=`)
			background := atoi(t, fx.expect(`bgpid=(\d+)=`))
			if got := fx.expect(`jobs=(\d+)=`); got != "1" {
				t.Errorf("jobs = %s", got)
			}
			fx.typeLine("echo shellpid=$$=")
			shell := atoi(t, fx.expect(`shellpid=(\d+)=`))

			fx.h.End(fx.ctx, protocol.SessionEnd{SessionID: fx.id})
			fx.send.awaitState(t, fx.id, protocol.SessionEnded)
			waitDead(t, "user shell", shell)
			waitDead(t, "user background job", background)
		})
	}
}

func TestSessionProcessesNeverIncludesTheAgent(t *testing.T) {
	for _, pid := range sessionProcesses(os.Getpid()) {
		if pid == os.Getpid() || pid <= 1 {
			t.Fatalf("sessionProcesses returned pid %d", pid)
		}
	}
	if len(processTable()) < 2 {
		t.Error("the process table could not be read")
	}
}
