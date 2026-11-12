//go:build linux

package swdeploy

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

func defaultEnv(platform.Platform) Env {
	return Env{OSName: "Linux", Managers: []string{protocol.ManagerApt, protocol.ManagerDnf}, Lookup: software.LookupTool}
}
