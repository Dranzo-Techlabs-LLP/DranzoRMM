//go:build darwin

package software

import (
	"context"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// appDirs are the system-wide application folders.
var appDirs = []string{"/Applications", "/System/Applications"}

func gatherOS(ctx context.Context, plat platform.Platform) ([]protocol.SoftwareItem, []string) {
	return GatherDarwin(ctx, plat, LookupTool, NewBrew(plat), appDirs)
}
