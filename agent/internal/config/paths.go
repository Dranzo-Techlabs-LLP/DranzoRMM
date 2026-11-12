// Package config manages the agent's on-disk configuration: the per-OS
// protected data directories, config.json, bootstrap.json and the small
// status file read by "dranzo-agent status".
package config

import (
	"path/filepath"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
)

// Paths locates the agent's data. StateDir holds keys, trust anchors and
// state; ConfigDir holds bootstrap.json. They differ only on Linux.
type Paths struct {
	StateDir  string
	ConfigDir string
}

// ResolvePaths returns the per-OS default directories, or dataDir for both
// when an override is given (development, containers and tests).
func ResolvePaths(dataDir string) Paths {
	if dataDir != "" {
		abs, err := filepath.Abs(dataDir)
		if err != nil {
			abs = dataDir
		}
		return Paths{StateDir: abs, ConfigDir: abs}
	}
	return defaultPaths()
}

// Ensure creates the directories with restrictive permissions.
func (p Paths) Ensure() error {
	if err := fsutil.EnsurePrivateDir(p.StateDir); err != nil {
		return err
	}
	if p.ConfigDir != p.StateDir {
		if err := fsutil.EnsurePrivateDir(p.ConfigDir); err != nil {
			return err
		}
	}
	return nil
}

// ConfigFile is config.json (server URL, device ID, intervals).
func (p Paths) ConfigFile() string { return filepath.Join(p.StateDir, "config.json") }

// BootstrapFile is bootstrap.json (server URL + enrollment token).
func (p Paths) BootstrapFile() string { return filepath.Join(p.ConfigDir, "bootstrap.json") }

// KeyFile is the device private key (PKCS#8 PEM).
func (p Paths) KeyFile() string { return filepath.Join(p.StateDir, "device.key") }

// CertFile is the device client certificate (PEM).
func (p Paths) CertFile() string { return filepath.Join(p.StateDir, "device.crt") }

// CAFile is the pinned CA bundle.
func (p Paths) CAFile() string { return filepath.Join(p.StateDir, "ca.pem") }

// TrustFile is trust.json (command signing keys).
func (p Paths) TrustFile() string { return filepath.Join(p.StateDir, "trust.json") }

// NoncesFile is nonces.json (replay protection).
func (p Paths) NoncesFile() string { return filepath.Join(p.StateDir, "nonces.json") }

// LogFile is agent.log.
func (p Paths) LogFile() string { return filepath.Join(p.StateDir, "agent.log") }

// StatusFile is the small connection status file read by the status command.
func (p Paths) StatusFile() string { return filepath.Join(p.StateDir, "status.json") }

// TempDir is the root-only directory for job temp files.
func (p Paths) TempDir() string { return filepath.Join(p.StateDir, "tmp") }
