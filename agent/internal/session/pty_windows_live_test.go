//go:build windows

package session

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// Live Windows tests (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit): a real Windows PowerShell on a real ConPTY,
// driven through the session handler exactly like a technician's terminal.

const liveWait = 60 * time.Second

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

func runningAsSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func waitProcessGone(t *testing.T, what string, pid int) {
	t.Helper()
	deadline := time.Now().Add(liveWait)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still running after the session ended", what, pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// vtRe matches the VT sequences ConPTY puts around the text.
var vtRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78]`)

type liveTerm struct {
	t    *testing.T
	h    *Handler
	send *fakeSender
	ui   *userui.Fake
	ctx  context.Context
	id   string
}

func newLiveTerm(t *testing.T, plat platform.Platform) *liveTerm {
	t.Helper()
	lt := &liveTerm{t: t, send: newSender(), ui: userui.NewFake()}
	lt.h = New(agentcore.Env{Sender: lt.send, Seq: protocol.NewSeqTracker(), Platform: plat, Log: logging.Discard()}, lt.ui, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	lt.ctx = ctx
	t.Cleanup(func() {
		cancel()
		lt.h.ConnectionLost()
	})
	return lt
}

func (lt *liveTerm) start(runAs string, cols, rows int) {
	lt.t.Helper()
	msg := startMsg(protocol.SessionKindTerminal, protocol.ConsentNone)
	msg.Terminal = &protocol.TerminalOptions{Cols: cols, Rows: rows, RunAs: runAs}
	lt.id = msg.SessionID
	lt.h.Start(lt.ctx, msg)
	lt.send.await(lt.t, "active or failed", func() bool {
		for _, s := range lt.send.statuses(lt.id) {
			if s.State == protocol.SessionActive {
				return true
			}
			if s.State == protocol.SessionFailed {
				lt.t.Fatalf("session failed: %s", s.Reason)
			}
		}
		return false
	})
}

// typeLine types a line and presses Enter (CR, as a terminal sends it).
func (lt *liveTerm) typeLine(line string) {
	lt.h.Input(lt.ctx, input(lt.id, line+"\r"))
}

func (lt *liveTerm) text() string {
	return vtRe.ReplaceAllString(string(lt.send.output(lt.t, lt.id)), "")
}

func (lt *liveTerm) expect(re string) string {
	lt.t.Helper()
	rx := regexp.MustCompile(re)
	deadline := time.Now().Add(liveWait)
	for {
		if m := rx.FindStringSubmatch(lt.text()); m != nil {
			return m[len(m)-1]
		}
		if time.Now().After(deadline) {
			raw := string(lt.send.output(lt.t, lt.id))
			if len(raw) > 4000 {
				raw = raw[len(raw)-4000:]
			}
			lt.t.Fatalf("terminal output never matched %q; raw output (tail):\n%q", re, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (lt *liveTerm) pid(re string) int {
	lt.t.Helper()
	n, err := strconv.Atoi(lt.expect(re))
	if err != nil || n <= 0 {
		lt.t.Fatalf("not a pid for %s: %v", re, err)
	}
	return n
}

func TestWindowsLiveTerminal(t *testing.T) {
	requireLiveWindows(t)
	// Nobody "logged in" from the handler's point of view, so the session
	// needs no consent; the terminal itself is the real ConPTY.
	lt := newLiveTerm(t, &platform.Fake{})
	lt.start(protocol.RunAsSystem, 100, 40)

	// The arithmetic proves that PowerShell evaluated the line: the typed
	// text never contains "dz-42".
	lt.typeLine(`Write-Output ("dz-" + (6*7))`)
	lt.expect(`dz-42`)

	lt.typeLine(`Write-Output ("size=" + $Host.UI.RawUI.WindowSize.Width + "x" + $Host.UI.RawUI.WindowSize.Height + "=")`)
	t.Logf("initial size: %s", lt.expect(`size=(\d+x\d+)=`))
	lt.h.Input(lt.ctx, protocol.SessionInput{SessionID: lt.id, Kind: protocol.SessionInputResize, Cols: 132, Rows: 43})
	time.Sleep(500 * time.Millisecond)
	lt.typeLine(`Write-Output ("resized=" + $Host.UI.RawUI.WindowSize.Width + "x" + $Host.UI.RawUI.WindowSize.Height + "=")`)
	if got := lt.expect(`resized=(\d+x\d+)=`); got != "132x43" {
		t.Errorf("after resize the console is %s, want 132x43", got)
	}

	lt.typeLine(`Write-Output ("who=" + [Security.Principal.WindowsIdentity]::GetCurrent().Name + "=")`)
	t.Logf("shell runs as %s (test runs as SYSTEM: %v)", lt.expect(`who=([^=\r\n]+)=`), runningAsSystem())

	lt.typeLine(`Write-Output ("shellpid=" + $PID + "=")`)
	shell := lt.pid(`shellpid=(\d+)=`)
	lt.typeLine(`$c = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\PING.EXE') -ArgumentList '-n','600','127.0.0.1' -WindowStyle Hidden -PassThru; Write-Output ("childpid=" + $c.Id + "=")`)
	child := lt.pid(`childpid=(\d+)=`)
	if !processAlive(shell) || !processAlive(child) {
		t.Fatalf("shell %d alive=%v child %d alive=%v", shell, processAlive(shell), child, processAlive(child))
	}

	lt.h.End(lt.ctx, protocol.SessionEnd{SessionID: lt.id})
	st := lt.send.awaitState(t, lt.id, protocol.SessionEnded)
	t.Logf("ended: reason %q", st.Reason)
	waitProcessGone(t, "shell", shell)
	waitProcessGone(t, "child started from the shell", child)
	if _, ok := lt.h.ActiveSession(lt.id); ok {
		t.Error("session still active")
	}
}

func TestWindowsLiveTerminalExit(t *testing.T) {
	requireLiveWindows(t)
	lt := newLiveTerm(t, &platform.Fake{})
	lt.start(protocol.RunAsSystem, 80, 25)
	lt.typeLine(`Write-Output ("shellpid=" + $PID + "=")`)
	shell := lt.pid(`shellpid=(\d+)=`)
	lt.typeLine("exit")
	st := lt.send.awaitState(t, lt.id, protocol.SessionEnded)
	if st.Reason != ReasonTerminalExited {
		t.Errorf("reason %q, want %q", st.Reason, ReasonTerminalExited)
	}
	waitProcessGone(t, "shell", shell)
}

// TestWindowsLiveTerminalConnectionLost: a lost control connection ends the
// terminal and everything started from it.
func TestWindowsLiveTerminalConnectionLost(t *testing.T) {
	requireLiveWindows(t)
	lt := newLiveTerm(t, &platform.Fake{})
	lt.start(protocol.RunAsSystem, 80, 25)
	lt.typeLine(`Write-Output ("shellpid=" + $PID + "=")`)
	shell := lt.pid(`shellpid=(\d+)=`)
	lt.typeLine(`$c = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\PING.EXE') -ArgumentList '-n','600','127.0.0.1' -WindowStyle Hidden -PassThru; Write-Output ("childpid=" + $c.Id + "=")`)
	child := lt.pid(`childpid=(\d+)=`)
	lt.h.ConnectionLost()
	waitProcessGone(t, "shell", shell)
	waitProcessGone(t, "child", child)
}

// TestWindowsLiveTerminalAsUser opens the terminal as the console user. It
// needs LocalSystem and a signed-in user (kit switch -AsSystem).
func TestWindowsLiveTerminalAsUser(t *testing.T) {
	requireLiveWindows(t)
	if !runningAsSystem() {
		t.Skip("a user terminal needs LocalSystem (run the kit with -AsSystem)")
	}
	plat := platform.New()
	u, err := plat.ConsoleUser(context.Background())
	if errors.Is(err, platform.ErrNoConsoleUser) {
		t.Skip("nobody is logged in at the console")
	}
	if err != nil {
		t.Fatalf("console user: %v", err)
	}
	lt := newLiveTerm(t, plat)
	lt.start(protocol.RunAsUser, 100, 30)
	lt.typeLine(`Write-Output ("who=" + [Security.Principal.WindowsIdentity]::GetCurrent().Name + "=" + (Get-Process -Id $PID).SessionId + "=")`)
	who := lt.expect(`who=([^\r\n]+=\d+)=`)
	t.Logf("user terminal: %s (console user %+v)", who, *u)
	if !strings.HasPrefix(strings.ToLower(who), strings.ToLower(u.Name)+"=") || !strings.HasSuffix(who, "="+strconv.FormatUint(uint64(u.SessionID), 10)) {
		t.Errorf("terminal runs as %q, want %s in session %d", who, u.Name, u.SessionID)
	}
	lt.typeLine(`Write-Output ("shellpid=" + $PID + "=")`)
	shell := lt.pid(`shellpid=(\d+)=`)
	lt.h.End(lt.ctx, protocol.SessionEnd{SessionID: lt.id})
	lt.send.awaitState(t, lt.id, protocol.SessionEnded)
	waitProcessGone(t, "user shell", shell)
	_, _, indicators, _ := lt.ui.Snapshot()
	t.Logf("indicator requests: %v", indicators)
}
