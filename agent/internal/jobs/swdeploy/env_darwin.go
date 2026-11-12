//go:build darwin

package swdeploy

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

func defaultEnv(plat platform.Platform) Env {
	return Env{OSName: "macOS", Managers: []string{protocol.ManagerBrew}, Lookup: software.LookupTool, Brew: software.NewBrew(plat)}
}
