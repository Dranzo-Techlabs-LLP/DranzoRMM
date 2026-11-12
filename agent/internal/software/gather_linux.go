//go:build linux

package software

import (
	"context"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func gatherOS(ctx context.Context, plat platform.Platform) ([]protocol.SoftwareItem, []string) {
	return GatherLinux(ctx, plat, LookupTool)
}
