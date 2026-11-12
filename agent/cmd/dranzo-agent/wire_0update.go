package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/svc"
	"github.com/dranzo/dranzormm/agent/internal/update"
)

func init() { features = append(features, wireUpdate) }

// wireUpdate installs the signed self-update handler (internal/update).
//
// A problem here never stops the agent: without a usable updater the agent
// keeps the core's default handler, which answers every offer with "failed".
func wireUpdate(a *agentcore.Agent) error {
	env := a.Env()
	exe, err := os.Executable()
	if err == nil {
		// The service may be registered through a symbolic link; the file
		// that is exchanged is the one it points to.
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		env.Log.Warn("self-update disabled: the path of the executable is unknown", slog.Any("error", err))
		return nil
	}
	running, foreground := update.RunMode(os.Args)
	u, err := update.New(update.Options{
		StateDir: env.Paths.StateDir,
		ExePath:  exe,
		Version:  env.Version,
		Log:      env.Log,
		Sender:   env.Sender,
		Blobs:    env.Blobs,
		Platform: env.Platform,
		Restarter: update.NewRestarter(update.RestartConfig{
			Service:     !foreground,
			ServiceName: svc.Name(),
			ExePath:     exe,
			Args:        os.Args,
			Log:         env.Log,
		}),
		Busy: func() bool {
			runningJobs, queued := a.Jobs().Active()
			return runningJobs+queued > 0
		},
	})
	if err != nil {
		env.Log.Warn("self-update disabled", slog.Any("error", err))
		return nil
	}
	a.SetUpdateHandler(u)
	a.OnHelloAck(u.HelloAck)
	if running {
		// Only "run" is a start of the agent: it counts as a start of a
		// pending version and arms the confirmation watchdog. Other
		// commands that build an agent ("enroll") must not.
		u.Start()
	}
	return nil
}
