//go:build windows

package update

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// minUptimeBeforeExit lets the Service Control Manager see the service
	// in the RUNNING state before the process exits, so that the exit counts
	// as a failure of a running service (which triggers the recovery action)
	// rather than as a failed start.
	minUptimeBeforeExit = 10 * time.Second
	// Recovery settings applied when the service has none (the same values
	// "dranzo-agent install" uses).
	recoveryDelay       = 5 * time.Second
	recoveryResetPeriod = 3600
)

// processStart approximates when this process started.
var processStart = time.Now()

func newRestarter(cfg RestartConfig) Restarter { return &exitRestarter{cfg: cfg} }

// exitRestarter ends the process with ExitCodeRestart.
//
// As a Windows service the process exits WITHOUT reporting SERVICE_STOPPED.
// The Service Control Manager treats that as an unexpected termination and
// runs the service's recovery action: "restart the service" after 5 seconds.
// This needs no helper process that would have to outlive the service, and
// the SCM (not the agent) is what starts the new binary. Prepare makes sure
// the recovery action exists before the binary is exchanged.
//
// In foreground mode the supervisor of the agent restarts it on ExitCodeRestart.
type exitRestarter struct {
	cfg RestartConfig
}

func (r *exitRestarter) Prepare() error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect service mode: %w", err)
	}
	if !isService {
		return nil
	}
	return ensureRestartOnFailure(r.cfg.ServiceName)
}

func (r *exitRestarter) Restart() error {
	if d := minUptimeBeforeExit - time.Since(processStart); d > 0 {
		time.Sleep(d)
	}
	r.cfg.Log.Info("exiting so that the new binary is started", slog.Int("exit_code", ExitCodeRestart))
	os.Exit(ExitCodeRestart)
	return nil
}

// ensureRestartOnFailure verifies that the service's recovery actions contain
// "restart the service" and configures it if they do not.
func ensureRestartOnFailure(serviceName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer func() { _ = s.Close() }()
	actions, err := s.RecoveryActions()
	if err == nil {
		for _, a := range actions {
			if a.Type == mgr.ServiceRestart {
				return nil
			}
		}
	}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: recoveryDelay}}, recoveryResetPeriod); err != nil {
		return fmt.Errorf("service %s has no restart-on-failure recovery action and it could not be set: %w", serviceName, err)
	}
	return nil
}
