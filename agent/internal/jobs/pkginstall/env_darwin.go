//go:build darwin

package pkginstall

import (
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

func defaultEnv(plat platform.Platform) Env {
	return Env{
		OSName:         "macOS",
		Types:          []string{TypePKG, TypeDMG},
		Detections:     []string{DetectFile, DetectPkgutil, DetectBrew, DetectApp},
		UninstallTools: []string{"pkgutil", "brew"},
		Lookup:         software.LookupTool,
		Brew:           software.NewBrew(plat),
		AppDirs:        []string{"/Applications", "/System/Applications"},
	}
}
