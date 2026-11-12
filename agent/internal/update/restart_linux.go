//go:build linux

package update

import (
	"errors"
	"os"
)

// serviceRestartCommand: "systemctl --no-block restart <unit>.service".
//
// --no-block makes systemctl return as soon as PID 1 has queued the restart
// job. From then on the job belongs to systemd: it stops this process (and
// everything else in the unit's control group, including the systemctl
// client) and starts the unit again from the binary now on disk.
//
// Under an init system other than systemd there is no uniform restart
// command; the caller then re-executes the agent in place.
func serviceRestartCommand(serviceName string) (string, []string, error) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return "", nil, errors.New("systemd is not the service manager of this system")
	}
	systemctl, err := firstExisting("/usr/bin/systemctl", "/bin/systemctl")
	if err != nil {
		return "", nil, err
	}
	return systemctl, []string{"--no-block", "restart", serviceName + ".service"}, nil
}
