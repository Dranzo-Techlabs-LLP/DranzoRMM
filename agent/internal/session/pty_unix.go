//go:build !windows

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// shellPlan is how the shell is started on this OS (see shell_*.go).
type shellPlan struct {
	path string
	args []string
	env  []string
	dir  string
	// cred switches the process to the user directly (nil: no switch, or the
	// switch is done by the command itself, e.g. runuser / sudo).
	cred *syscall.Credential
	// ttyUID / ttyGID own the terminal device (-1: leave it to the agent).
	ttyUID int
	ttyGID int
}

type unixTerminal struct {
	ptmx *os.File
	cmd  *exec.Cmd
	done chan struct{}

	killOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

// startTerminal starts a login shell on a new pseudo-terminal. The shell is
// the leader of a new session with the PTY as its controlling terminal, so
// it has job control and the whole session can be found and killed later.
func startTerminal(ctx context.Context, spec TerminalSpec) (Terminal, error) {
	plan, err := planShell(ctx, spec)
	if err != nil {
		return nil, err
	}
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, fmt.Errorf("open pseudo-terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()
	if err := pty.Setsize(ptmx, winsize(spec.Cols, spec.Rows)); err != nil {
		_ = ptmx.Close()
		return nil, fmt.Errorf("set terminal size: %w", err)
	}
	if plan.ttyUID >= 0 {
		// Like login(1) and sshd: the terminal device belongs to its user.
		if err := tty.Chown(plan.ttyUID, plan.ttyGID); err != nil {
			_ = ptmx.Close()
			return nil, fmt.Errorf("hand the terminal to the user: %w", err)
		}
		_ = tty.Chmod(0o620)
	}
	cmd := exec.Command(plan.path, plan.args...)
	cmd.Env = plan.env
	cmd.Dir = plan.dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Setctty:    true, // fd 0 (the PTY) becomes the controlling terminal
		Credential: plan.cred,
	}
	if err := cmd.Start(); err != nil {
		_ = ptmx.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}
	t := &unixTerminal{ptmx: ptmx, cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(t.done)
	}()
	return t, nil
}

func winsize(cols, rows int) *pty.Winsize {
	return &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)} //nolint:gosec // G115: validated to 1..1000
}

func (t *unixTerminal) Read(p []byte) (int, error)  { return t.ptmx.Read(p) }
func (t *unixTerminal) Write(p []byte) (int, error) { return t.ptmx.Write(p) }
func (t *unixTerminal) Done() <-chan struct{}       { return t.done }
func (t *unixTerminal) PID() int                    { return t.cmd.Process.Pid }

func (t *unixTerminal) Resize(cols, rows int) error {
	return pty.Setsize(t.ptmx, winsize(cols, rows))
}

// Kill terminates every process of the terminal's session and every
// descendant of the shell: first SIGHUP (what a closing terminal sends, so
// shells can save their history), then SIGKILL until nothing is left.
func (t *unixTerminal) Kill() {
	t.killOnce.Do(func() {
		leader := t.cmd.Process.Pid
		signalAll := func(sig syscall.Signal) int {
			victims := sessionProcesses(leader)
			for _, pid := range victims {
				_ = syscall.Kill(pid, sig)
			}
			return len(victims)
		}
		signalAll(syscall.SIGHUP)
		select {
		case <-t.done:
		case <-time.After(250 * time.Millisecond):
		}
		for i := 0; i < 50; i++ {
			n := signalAll(syscall.SIGKILL)
			// The process group of the leader, in case the process table
			// could not be read.
			_ = syscall.Kill(-leader, syscall.SIGKILL)
			if n == 0 {
				select {
				case <-t.done:
					return
				default:
				}
			}
			select {
			case <-t.done:
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
}

func (t *unixTerminal) Close() error {
	t.closeOnce.Do(func() { t.closeErr = t.ptmx.Close() })
	return t.closeErr
}

// procInfo is one row of the process table.
type procInfo struct {
	pid, ppid, sid int
}

// sessionProcesses returns the processes that belong to the terminal: the
// members of the session led by leader plus all descendants of leader
// (a helper such as sudo may have put the shell into a session of its own).
// The agent itself and pid 1 are never included.
func sessionProcesses(leader int) []int {
	table := processTable()
	self := os.Getpid()
	children := map[int][]int{}
	for _, p := range table {
		children[p.ppid] = append(children[p.ppid], p.pid)
	}
	want := map[int]bool{}
	for _, p := range table {
		if p.sid == leader {
			want[p.pid] = true
		}
	}
	queue := []int{leader}
	seen := map[int]bool{leader: true}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range children[pid] {
			if !seen[c] {
				seen[c] = true
				want[c] = true
				queue = append(queue, c)
			}
		}
	}
	for _, p := range table {
		if p.pid == leader {
			want[leader] = true
		}
	}
	out := make([]int, 0, len(want))
	for pid := range want {
		if pid > 1 && pid != self {
			out = append(out, pid)
		}
	}
	return out
}

// errNotRoot explains why a shell cannot be started as another user.
var errNotRoot = errors.New("the agent is not running as root and cannot start a shell as another user")
