//go:build windows

package svc

import (
	"fmt"

	"github.com/kardianos/service"

	"github.com/dranzo/dranzormm/agent/internal/config"
)

const serviceName = "DranzoRMMAgent"

func serviceOptions() service.KeyValue {
	return service.KeyValue{
		// Service Control Manager recovery: restart 5 s after a failure.
		"OnFailure":              "restart",
		"OnFailureDelayDuration": "5s",
		"OnFailureResetPeriod":   3600,
	}
}

// SelfUninstall removes the service from inside the running service
// (agent.uninstall). The service is marked for deletion, the data is purged
// and a stop is requested; Windows removes the service once the process exits.
// The program files themselves are removed by the installer package (MSI).
func SelfUninstall(p config.Paths) error {
	s, err := New(nil, nil, nil)
	if err != nil {
		return err
	}
	uerr := s.Uninstall()
	Purge(p)
	if serr := s.Stop(); serr != nil {
		return fmt.Errorf("stop service: %w", serr)
	}
	if uerr != nil {
		return fmt.Errorf("remove service: %w", uerr)
	}
	return nil
}
