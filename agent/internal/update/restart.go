package update

import "log/slog"

// ExitCodeRestart is the exit status with which the agent ends on Windows
// when it must be started again to complete an update or a rollback (the
// binary on disk was exchanged; a running image cannot replace itself there).
// Under the Service Control Manager the exit is an unexpected termination, so
// the service's recovery action starts it again. In foreground mode whatever
// supervises the agent (a wrapper script, a container runtime, a test) must
// start it again when it sees this status. 75 is EX_TEMPFAIL of sysexits.h.
const ExitCodeRestart = 75

// Restarter replaces the running agent process by the binary that is now at
// the executable path.
type Restarter interface {
	// Prepare is called before the binary is exchanged. An error aborts the
	// update: it means nobody would start the agent again afterwards.
	Prepare() error
	// Restart hands over to the binary on disk. It does not return when it
	// succeeds; an error means this process keeps running.
	Restart() error
}

// RestartConfig describes how the running agent was started.
type RestartConfig struct {
	// Service is true when the agent runs under the OS service manager
	// ("dranzo-agent run" without --foreground).
	Service bool
	// ServiceName is the OS-level service name (systemd unit without
	// ".service", launchd label, Windows service name).
	ServiceName string
	// ExePath is the installed executable.
	ExePath string
	// Args are the arguments of the running process (os.Args).
	Args []string
	Log  *slog.Logger
}

// NewRestarter returns the restart mechanism for this OS and start mode:
//
//	Linux, service:    systemctl --no-block restart <unit>   (fallback: exec in place)
//	macOS, service:    launchctl kickstart -k system/<label> (fallback: exec in place)
//	Unix, foreground:  exec in place (same PID, same arguments, same environment)
//	Windows, any mode: exit with ExitCodeRestart
func NewRestarter(cfg RestartConfig) Restarter {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return newRestarter(cfg)
}
