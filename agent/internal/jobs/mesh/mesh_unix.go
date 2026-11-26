//go:build !windows

package mesh

import (
	"os"
	"os/exec"
	"runtime"
)

const binaryName = "meshagent"

// defaultInstalledPaths are where "meshagent -fullinstall" puts the agent on
// macOS and Linux (service name "meshagent").
func defaultInstalledPaths() []string {
	return []string{
		"/usr/local/mesh_services/meshagent/meshagent",
		"/usr/local/mesh/meshagent",
	}
}

// defaultRestartCommand restarts the "meshagent" service: launchd label
// "meshagent" on macOS (verified on macOS 12 and 26), the systemd unit
// "meshagent" on Linux.
func defaultRestartCommand() []string {
	if runtime.GOOS == "darwin" {
		return []string{"/bin/launchctl", "kickstart", "-k", "system/meshagent"}
	}
	systemctl := "/bin/systemctl"
	if p, err := exec.LookPath("systemctl"); err == nil {
		systemctl = p
	}
	return []string{systemctl, "restart", "meshagent"}
}

// makeExecutable marks the downloaded binary executable for root only.
func makeExecutable(path string) error { return os.Chmod(path, 0o700) } //nolint:gosec // G302: an executable needs the execute bit; owner only
