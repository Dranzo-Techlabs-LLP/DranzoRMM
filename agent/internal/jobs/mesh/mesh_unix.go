//go:build !windows

package mesh

import "os"

const binaryName = "meshagent"

// defaultInstalledPaths are where "meshagent -fullinstall" puts the agent on
// macOS and Linux (service name "meshagent").
func defaultInstalledPaths() []string {
	return []string{
		"/usr/local/mesh_services/meshagent/meshagent",
		"/usr/local/mesh/meshagent",
	}
}

// makeExecutable marks the downloaded binary executable for root only.
func makeExecutable(path string) error { return os.Chmod(path, 0o700) } //nolint:gosec // G302: an executable needs the execute bit; owner only
