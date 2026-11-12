//go:build darwin

package patch

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// osName is used in "not supported" messages.
const osName = "macOS"

func osProviders(plat platform.Platform) []Provider {
	return []Provider{
		&SoftwareUpdateProvider{Plat: plat, Lookup: software.LookupTool},
		&BrewProvider{Brew: software.NewBrew(plat)},
	}
}
