//go:build !windows

package software

import (
	"os"
	"path/filepath"
	"strings"
)

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// LookupTool returns the absolute path of a system tool, or "" when it is
// not installed. Tools that the agent runs as root are only taken from
// root-owned system directories, never from $PATH, so that a user-writable
// directory on the service's search path cannot plant a binary. Homebrew is
// the exception (it lives in a user-owned prefix) and is never run as root.
func LookupTool(name string) string {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return ""
	}
	if name == "brew" {
		for _, p := range brewPaths {
			if isExecutable(p) {
				return p
			}
		}
		return ""
	}
	for _, dir := range systemToolDirs {
		if p := filepath.Join(dir, name); isExecutable(p) {
			return p
		}
	}
	return ""
}
