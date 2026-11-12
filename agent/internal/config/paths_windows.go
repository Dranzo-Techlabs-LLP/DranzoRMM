//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func defaultPaths() Paths {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	dir := filepath.Join(base, "DranzoRMM")
	return Paths{StateDir: dir, ConfigDir: dir}
}
