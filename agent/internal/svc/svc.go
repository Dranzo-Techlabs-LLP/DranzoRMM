// Package svc wraps github.com/kardianos/service: installing the agent as a
// normal, visible OS service (Windows service / launchd daemon / systemd
// unit), running under the service manager, and removing it again.
//
// Transparency: the service has a descriptive display name and description,
// appears in the OS service list, and can be removed by any administrator of
// the device. The optional uninstall code only protects the agent's own
// "uninstall" command.
package svc

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kardianos/service"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Service identity shown by the OS.
const (
	DisplayName = "DranzoRMM Agent"
	Description = "DranzoRMM endpoint management agent. It lets your IT provider monitor, maintain and support this computer " +
		"(inventory, software updates, scripts and remote support). It is installed and managed by your IT provider " +
		"and can be removed by an administrator of this computer."
)

// RunFunc is the agent main loop; it must return when ctx is cancelled.
type RunFunc func(ctx context.Context) error

type program struct {
	run    RunFunc
	log    *slog.Logger
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
}

func (p *program) Start(service.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.run == nil {
		return errors.New("no run function")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := p.run(ctx); err != nil && ctx.Err() == nil {
			if p.log != nil {
				p.log.Error("agent stopped with an error", slog.Any("error", err))
			}
			// Exit non-zero so the service manager's restart-on-failure applies.
			os.Exit(1)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
	}
	return nil
}

func newConfig(args []string) *service.Config {
	return &service.Config{
		Name:        serviceName,
		DisplayName: DisplayName,
		Description: Description,
		Arguments:   args,
		Option:      serviceOptions(),
	}
}

// New builds the service object. run may be nil for control operations
// (install, uninstall, start, stop, status).
func New(run RunFunc, log *slog.Logger, args []string) (service.Service, error) {
	return service.New(&program{run: run, log: log}, newConfig(args))
}

// Name returns the OS-level service name.
func Name() string { return serviceName }

// Interactive reports whether the process was started from a terminal rather
// than by the service manager.
func Interactive() bool { return service.Interactive() }

// Register registers the service with the OS service manager (it will be
// started with the given arguments). It fails if the service already exists.
func Register(args []string) error {
	s, err := New(nil, nil, args)
	if err != nil {
		return err
	}
	if err := s.Install(); err != nil {
		return fmt.Errorf("register service: %w", err)
	}
	return nil
}

// Start starts the registered service.
func Start() error {
	s, err := New(nil, nil, nil)
	if err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// Uninstall stops and removes the service. A service that is not installed is not an error.
func Uninstall() error {
	s, err := New(nil, nil, nil)
	if err != nil {
		return err
	}
	// A service definition that does not exist (never installed, or owned by
	// an OS package instead of "dranzo-agent install") is not an error. Ask
	// first: kardianos/service's Windows Uninstall reports a missing service
	// with a plain fmt error ("service X is not installed"), not ErrNotInstalled.
	if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
		return nil
	}
	_ = s.Stop()
	if err := s.Uninstall(); err != nil && !errors.Is(err, service.ErrNotInstalled) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove service: %w", err)
	}
	return nil
}

// Status returns "running", "stopped" or "not installed / unknown".
func Status() string {
	s, err := New(nil, nil, nil)
	if err != nil {
		return "unknown"
	}
	st, err := s.Status()
	if err != nil {
		return "not installed"
	}
	switch st {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Run runs the agent under the service manager and blocks until the service stops.
func Run(run RunFunc, log *slog.Logger) error {
	s, err := New(run, log, nil)
	if err != nil {
		return err
	}
	return s.Run()
}

// ErrUninstallCode is returned when the uninstall code is missing or wrong.
var ErrUninstallCode = errors.New("a valid uninstall code is required (use --code)")

// VerifyUninstallCode checks code against the stored PBKDF2-HMAC-SHA256
// verifier in constant time. A nil verifier means no code is required.
func VerifyUninstallCode(code string, uc *protocol.UninstallCode) error {
	if uc == nil {
		return nil
	}
	salt, err := base64.StdEncoding.DecodeString(uc.Salt)
	if err != nil || len(salt) == 0 {
		return errors.New("stored uninstall code is invalid")
	}
	want, err := base64.StdEncoding.DecodeString(uc.Hash)
	if err != nil || len(want) != sha256.Size {
		return errors.New("stored uninstall code is invalid")
	}
	if uc.Iterations < 1 || uc.Iterations > 10_000_000 {
		return errors.New("stored uninstall code is invalid")
	}
	got, err := pbkdf2.Key(sha256.New, code, salt, uc.Iterations, len(want))
	if err != nil {
		return fmt.Errorf("derive uninstall code: %w", err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrUninstallCode
	}
	return nil
}

// Purge removes the agent's own files from its data directories (identity,
// trust anchors, configuration, state, logs). Only known file names are
// removed, and the directories only if they are then empty, so a
// mis-configured path can never delete unrelated data.
func Purge(p config.Paths) {
	files := []string{
		p.ConfigFile(), p.BootstrapFile(), p.KeyFile(), p.CertFile(),
		p.KeyFile() + ".next", p.CertFile() + ".next",
		p.CAFile(), p.TrustFile(), p.NoncesFile(), p.StatusFile(),
		p.LogFile(), p.LogFile() + ".1", p.LogFile() + ".2", p.LogFile() + ".3",
	}
	for _, f := range files {
		_ = os.Remove(f)
	}
	files = append(files, filepath.Join(p.StateDir, "update-state.json"), filepath.Join(p.StateDir, "failed-updates.json"))
	for _, f := range files[len(files)-2:] {
		_ = os.Remove(f)
	}
	_ = os.RemoveAll(filepath.Join(p.StateDir, "update-staging"))
	_ = os.RemoveAll(p.TempDir())
	_ = os.Remove(p.StateDir)
	if p.ConfigDir != p.StateDir {
		_ = os.Remove(p.ConfigDir)
	}
}
