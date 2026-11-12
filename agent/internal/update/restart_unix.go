//go:build !windows

package update

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	// serviceCommandTimeout bounds the service manager's control command.
	serviceCommandTimeout = 30 * time.Second
	// serviceStopWait is how long the agent waits to be stopped after the
	// service manager accepted the restart. It is longer than the agent's
	// own graceful shutdown (30 s), so a slow stop is not mistaken for a
	// restart that never happened.
	serviceStopWait = 60 * time.Second
)

func newRestarter(cfg RestartConfig) Restarter {
	if cfg.Service {
		return &serviceRestarter{cfg: cfg, command: serviceRestartCommand, wait: serviceStopWait}
	}
	return &execRestarter{cfg: cfg}
}

// execRestarter replaces the process image in place. The PID, the arguments
// and the environment stay the same, so whatever started the agent (a shell,
// a container runtime, an init system) keeps supervising the same process.
type execRestarter struct {
	cfg RestartConfig
	// exec is syscall.Exec (replaced in tests).
	exec func(argv0 string, argv []string, envv []string) error
}

func (r *execRestarter) Prepare() error { return nil }

func (r *execRestarter) Restart() error {
	args := r.cfg.Args
	if len(args) == 0 {
		args = []string{r.cfg.ExePath}
	}
	execFn := r.exec
	if execFn == nil {
		execFn = syscall.Exec
	}
	// Only returns on failure.
	if err := execFn(r.cfg.ExePath, args, os.Environ()); err != nil {
		return fmt.Errorf("exec %s: %w", r.cfg.ExePath, err)
	}
	return nil
}

// serviceRestarter asks the service manager to restart the service. The
// request is carried out by the service manager itself (PID 1), not by a
// child of this process, so it survives this process being stopped.
type serviceRestarter struct {
	cfg RestartConfig
	// command returns the control command for this OS (see restart_<os>.go).
	command func(serviceName string) (path string, args []string, err error)
	wait    time.Duration
	// exec is passed to the in-place fallback (nil: syscall.Exec).
	exec func(argv0 string, argv []string, envv []string) error
}

func (r *serviceRestarter) Prepare() error { return nil }

func (r *serviceRestarter) Restart() error {
	err := r.viaServiceManager()
	if err == nil {
		// The service manager stops this process now.
		time.Sleep(r.wait)
		err = fmt.Errorf("the service manager accepted the restart but this process was not stopped within %s", r.wait)
	}
	// Still alive: the service manager is absent, is not the one supervising
	// this process, or refused. Replacing the process image has the same
	// effect and needs nothing but the kernel.
	r.cfg.Log.Warn("restart through the service manager failed; re-executing in place", slog.Any("error", err))
	return (&execRestarter{cfg: r.cfg, exec: r.exec}).Restart()
}

func (r *serviceRestarter) viaServiceManager() error {
	path, args, err := r.command(r.cfg.ServiceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	// Own session: the control command is not in this process's group, so
	// it is not signalled together with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// The control command is a child of this service. A service manager that
	// stops the service signals every process of the service, the control
	// command included, often before it has exited (observed with systemd:
	// "systemctl --no-block restart" ends with SIGTERM). Being killed by a
	// signal therefore means the restart is under way, not that it failed;
	// a refused request ends with an exit status instead.
	var exit *exec.ExitError
	if ctx.Err() == nil && errors.As(err, &exit) {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return nil
		}
	}
	return fmt.Errorf("%s %s: %w: %s", path, strings.Join(args, " "), err, clip(strings.TrimSpace(string(out))))
}

// firstExisting returns the first candidate that is a regular file. Control
// commands are looked up in fixed system directories, never through PATH.
func firstExisting(candidates ...string) (string, error) {
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
			return c, nil
		}
	}
	return "", errors.New(candidates[0] + " not found")
}
