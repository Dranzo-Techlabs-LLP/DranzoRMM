//go:build linux

package userui

import "github.com/dranzo/dranzormm/agent/internal/platform"

// New returns the UI for this operating system.
func New(plat platform.Platform) UI {
	ui := newLinuxUI(plat)
	ui.procEnv = graphicalProcEnv
	ui.writeTTY = writeTTY
	ui.endFile = createEndFile
	return ui
}
