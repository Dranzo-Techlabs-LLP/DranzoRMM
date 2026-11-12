//go:build linux

package patch

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// osName is used in "not supported" messages.
const osName = "Linux"

func osProviders(plat platform.Platform) []Provider {
	return []Provider{
		&AptProvider{Plat: plat, Lookup: software.LookupTool, HistoryLog: "/var/log/apt/history.log"},
		&DnfProvider{Plat: plat, Lookup: software.LookupTool},
	}
}
