//go:build darwin

package svc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/kardianos/service"

	"github.com/dranzo/dranzormm/agent/internal/config"
)

// serviceName is the launchd label; the daemon is defined by
// /Library/LaunchDaemons/<serviceName>.plist.
const serviceName = "com.dranzormm.agent"

func serviceOptions() service.KeyValue {
	return service.KeyValue{
		"KeepAlive": true, // launchd restarts the daemon if it exits
		"RunAtLoad": true,
	}
}

// SelfUninstall removes the daemon from inside the running daemon
// (agent.uninstall). Order matters: unloading the job kills this process, so
// the plist and the data are removed first and "launchctl remove" comes last.
func SelfUninstall(p config.Paths) error {
	plist := "/Library/LaunchDaemons/" + serviceName + ".plist"
	if err := os.Remove(plist); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", plist, err)
	}
	Purge(p)
	if err := exec.Command("/bin/launchctl", "remove", serviceName).Run(); err != nil {
		return fmt.Errorf("launchctl remove: %w", err)
	}
	return nil
}
