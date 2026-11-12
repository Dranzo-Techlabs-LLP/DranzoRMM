//go:build windows

package mesh

import (
	"os"
	"path/filepath"
)

const binaryName = "meshagent.exe"

// defaultInstalledPaths are where "meshagent.exe -fullinstall" puts the
// agent on Windows (service "Mesh Agent").
func defaultInstalledPaths() []string {
	var paths []string
	for _, env := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"} {
		if dir := os.Getenv(env); dir != "" {
			paths = append(paths, filepath.Join(dir, "Mesh Agent", "MeshAgent.exe"))
		}
	}
	if len(paths) == 0 {
		paths = []string{`C:\Program Files\Mesh Agent\MeshAgent.exe`}
	}
	return paths
}

// makeExecutable: nothing to do on Windows; the file inherits the ACL of the
// agent's protected data directory (SYSTEM and Administrators only).
func makeExecutable(string) error { return nil }
