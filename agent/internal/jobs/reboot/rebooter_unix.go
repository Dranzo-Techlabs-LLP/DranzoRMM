//go:build !windows

package reboot

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

func newOSRebooter(plat platform.Platform) Rebooter {
	return &ShutdownRebooter{Plat: plat, Lookup: software.LookupTool, Args: UnixShutdownArgs}
}
