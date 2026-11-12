//go:build windows

package patch

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// osName is used in "not supported" messages.
const osName = "Windows"

func osProviders(plat platform.Platform) []Provider {
	return []Provider{
		&WUAProvider{Plat: plat, Lookup: software.LookupTool},
		&WingetProvider{Plat: plat, Lookup: software.LookupTool},
	}
}
