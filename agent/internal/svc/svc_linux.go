//go:build linux

package svc

import (
	"errors"
	"fmt"
	"os"

	"github.com/kardianos/service"

	"github.com/dranzo/dranzormm/agent/internal/config"
)

// serviceName is the systemd unit name (dranzormm-agent.service).
const serviceName = "dranzormm-agent"

func serviceOptions() service.KeyValue {
	return service.KeyValue{
		"Restart": "always", // systemd restarts the service if it exits
	}
}

// SelfUninstall removes the service from inside the running service
// (agent.uninstall). Order matters: stopping the unit kills this process, so
// the unit is disabled and removed and the data purged first; stop comes last.
func SelfUninstall(p config.Paths) error {
	s, err := New(nil, nil, nil)
	if err != nil {
		return err
	}
	// Uninstall disables the unit and deletes the unit file written by
	// "dranzo-agent install". When the unit is owned by the OS package
	// (/usr/lib/systemd/system) only the disable step applies; either way the
	// agent goes on to delete its identity and stop.
	uerr := s.Uninstall()
	if errors.Is(uerr, os.ErrNotExist) {
		uerr = nil
	}
	Purge(p)
	if serr := s.Stop(); serr != nil {
		return fmt.Errorf("stop service: %w", serr)
	}
	if uerr != nil {
		return fmt.Errorf("remove service: %w", uerr)
	}
	return nil
}
