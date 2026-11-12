//go:build linux

package pkginstall

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

func defaultEnv(platform.Platform) Env {
	return Env{
		OSName:         "Linux",
		Types:          []string{TypeDEB, TypeRPM},
		Detections:     []string{DetectFile, DetectDpkg, DetectRpm},
		UninstallTools: []string{"apt-get", "dpkg", "dnf", "rpm", "snap", "flatpak"},
		Lookup:         software.LookupTool,
	}
}
