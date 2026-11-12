//go:build darwin

package userui

import "github.com/dranzo/dranzormm/agent/internal/platform"

// New returns the UI for this operating system.
func New(plat platform.Platform) UI { return newMacUI(plat) }
