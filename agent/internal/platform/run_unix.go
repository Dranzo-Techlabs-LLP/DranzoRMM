//go:build !windows

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// waitDelay bounds how long Run waits for output pipes that a background
// grandchild keeps open after the main process has exited.
const waitDelay = 3 * time.Second

type native struct{}

func newNative() Platform { return &native{} }

// run starts cmd in its own process group, waits for it and kills the whole
// group if ctx ends first.
func run(ctx context.Context, cmd *exec.Cmd) (int, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		return ExitCodeUnknown, fmt.Errorf("start %s: %w", cmd.Path, err)
	}
	pgid := cmd.Process.Pid
	var err error
	done := make(chan struct{})
	go func() {
		err = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// Negative pid: signal every process in the group (the process tree).
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
		return ExitCodeUnknown, ctx.Err()
	}
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return ExitCodeUnknown, err
		}
	}
	if cmd.ProcessState == nil {
		return ExitCodeUnknown, errors.New("process state unavailable")
	}
	code := cmd.ProcessState.ExitCode()
	if code < 0 {
		// Terminated by a signal: report the shell convention 128+signal.
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	}
	return code, nil
}

func (n *native) Run(ctx context.Context, c Command) (int, error) {
	if c.Path == "" {
		return ExitCodeUnknown, errors.New("empty command")
	}
	var cmd *exec.Cmd
	if c.AsUser == nil {
		cmd = exec.Command(c.Path, c.Args...)
		cmd.Env = MergeEnv(os.Environ(), c.Env, false)
	} else {
		var err error
		cmd, err = userCommand(c)
		if err != nil {
			return ExitCodeUnknown, err
		}
	}
	cmd.Dir = c.Dir
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	return run(ctx, cmd)
}

// baseUserEnv is the minimal environment for a command run as u.
func baseUserEnv(u *User) []string {
	env := []string{
		"USER=" + u.Name,
		"LOGNAME=" + u.Name,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
	}
	if u.Home != "" {
		env = append(env, "HOME="+u.Home)
	}
	if u.Shell != "" {
		env = append(env, "SHELL="+u.Shell)
	}
	if lang := os.Getenv("LANG"); lang != "" {
		env = append(env, "LANG="+lang)
	}
	return env
}

func (n *native) GrantUser(path string, u *User) error {
	if u == nil {
		return errors.New("no user")
	}
	uid, err := strconv.Atoi(u.UID)
	if err != nil {
		return fmt.Errorf("invalid uid %q", u.UID)
	}
	gid, err := strconv.Atoi(u.GID)
	if err != nil {
		return fmt.Errorf("invalid gid %q", u.GID)
	}
	// Lchown: never follow a symlink out of the directory we created.
	return os.Lchown(path, uid, gid)
}

// output runs a fixed helper command with a timeout and returns its stdout.
func output(ctx context.Context, timeout time.Duration, path string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if len(out) > 1<<20 {
		out = out[:1<<20]
	}
	return string(out), err
}
