//go:build !windows

package update

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var quiet = slog.New(slog.DiscardHandler)

type execCall struct {
	argv0 string
	argv  []string
	env   []string
}

func recordExec(calls *[]execCall, err error) func(string, []string, []string) error {
	return func(argv0 string, argv []string, envv []string) error {
		*calls = append(*calls, execCall{argv0, argv, envv})
		return err
	}
}

func TestExecRestarterKeepsArgumentsAndEnvironment(t *testing.T) {
	t.Setenv("DRANZO_TEST_MARKER", "kept")
	var calls []execCall
	args := []string{"dranzo-agent", "run", "--foreground", "--data-dir", "/var/lib/x"}
	r := &execRestarter{cfg: RestartConfig{ExePath: "/opt/dranzo/dranzo-agent", Args: args}, exec: recordExec(&calls, nil)}
	if err := r.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := r.Restart(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].argv0 != "/opt/dranzo/dranzo-agent" || strings.Join(calls[0].argv, " ") != strings.Join(args, " ") {
		t.Fatalf("exec calls: %+v", calls)
	}
	if !strings.Contains(strings.Join(calls[0].env, "\n"), "DRANZO_TEST_MARKER=kept") {
		t.Fatal("the environment was not passed on")
	}

	// A failing exec is an error: the caller keeps running.
	calls = nil
	r = &execRestarter{cfg: RestartConfig{ExePath: "/nonexistent"}, exec: recordExec(&calls, errors.New("ENOENT"))}
	if err := r.Restart(); err == nil || !strings.Contains(err.Error(), "/nonexistent") {
		t.Fatalf("error: %v", err)
	}
	if len(calls) != 1 || len(calls[0].argv) != 1 || calls[0].argv[0] != "/nonexistent" {
		t.Fatalf("argv without Args: %+v", calls)
	}
}

func TestNewRestarterSelectsByMode(t *testing.T) {
	if _, ok := NewRestarter(RestartConfig{Service: false}).(*execRestarter); !ok {
		t.Error("foreground mode must re-exec in place")
	}
	if _, ok := NewRestarter(RestartConfig{Service: true, ServiceName: "x"}).(*serviceRestarter); !ok {
		t.Error("service mode must go through the service manager")
	}
}

// script writes an executable shell script and returns its path.
func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ctl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServiceRestarterRunsTheControlCommand(t *testing.T) {
	out := filepath.Join(t.TempDir(), "args")
	ctl := script(t, `echo "$@" > "`+out+`"`)
	var calls []execCall
	r := &serviceRestarter{
		cfg: RestartConfig{ServiceName: "dranzormm-agent", ExePath: "/opt/x/dranzo-agent", Log: quiet},
		command: func(name string) (string, []string, error) {
			return ctl, []string{"--no-block", "restart", name + ".service"}, nil
		},
		wait: 10 * time.Millisecond,
		exec: recordExec(&calls, nil),
	}
	// In the test nobody stops the process, so after the wait the in-place
	// fallback runs: the agent is restarted one way or the other.
	if err := r.Restart(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the control command did not run: %v", err)
	}
	if strings.TrimSpace(string(got)) != "--no-block restart dranzormm-agent.service" {
		t.Fatalf("control command arguments: %q", got)
	}
	if len(calls) != 1 || calls[0].argv0 != "/opt/x/dranzo-agent" {
		t.Fatalf("fallback exec: %+v", calls)
	}
}

func TestServiceRestarterFallsBackToExec(t *testing.T) {
	for name, command := range map[string]func(string) (string, []string, error){
		"no service manager": func(string) (string, []string, error) { return "", nil, errors.New("systemd is not running") },
		"command fails":      func(string) (string, []string, error) { return script(t, "echo refused >&2; exit 3"), nil, nil },
		"command missing":    func(string) (string, []string, error) { return "/nonexistent/systemctl", nil, nil },
	} {
		var calls []execCall
		r := &serviceRestarter{cfg: RestartConfig{ExePath: "/opt/x/dranzo-agent", Log: quiet}, command: command, wait: time.Hour, exec: recordExec(&calls, nil)}
		done := make(chan error, 1)
		go func() { done <- r.Restart() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: waited for a stop although the control command failed", name)
		}
		if len(calls) != 1 {
			t.Errorf("%s: %d exec calls", name, len(calls))
		}
	}
}

// systemd stops the control command together with the service it restarts:
// a control command that dies from a signal means "restart under way". The
// agent must then wait to be stopped instead of re-executing itself in the
// middle of the service manager's stop.
func TestServiceRestarterTreatsKilledControlCommandAsAccepted(t *testing.T) {
	var calls []execCall
	r := &serviceRestarter{
		cfg:     RestartConfig{ExePath: "/opt/x/dranzo-agent", Log: quiet},
		command: func(string) (string, []string, error) { return script(t, "kill -TERM $$; sleep 5"), nil, nil },
		wait:    300 * time.Millisecond,
		exec:    recordExec(&calls, nil),
	}
	if err := r.viaServiceManager(); err != nil {
		t.Fatalf("a control command killed by a signal was treated as a failure: %v", err)
	}
	if len(calls) != 0 {
		t.Fatal("exec was called")
	}
	// Only if the stop never arrives does the fallback run, after the wait.
	start := time.Now()
	if err := r.Restart(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || time.Since(start) < r.wait {
		t.Fatalf("fallback after %s with %d exec calls", time.Since(start), len(calls))
	}
}

func TestServiceRestartCommand(t *testing.T) {
	path, args, err := serviceRestartCommand("some-service")
	if err != nil {
		// No service manager on this machine (for example Linux without systemd).
		t.Skip(err)
	}
	if !filepath.IsAbs(path) || len(args) == 0 {
		t.Fatalf("command: %s %v", path, args)
	}
	if !strings.Contains(strings.Join(args, " "), "some-service") {
		t.Fatalf("the service is not named: %v", args)
	}
}
