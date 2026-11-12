package software

import (
	"context"
	"fmt"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Brew builds Homebrew commands that never run as root (PROTOCOL.md section
// 6.2: "brew operations always run as the console user, never as root").
//
// When the agent runs as root (the installed service) every brew command is
// run in the console user's session; if nobody is logged in the command is
// refused with platform.ErrNoConsoleUser. When the agent itself runs
// unprivileged (development) brew runs as that user.
type Brew struct {
	// Path is the absolute path of the brew executable ("" if not installed).
	Path string
	Plat platform.Platform
	// IsRoot reports whether the agent runs with root privileges.
	IsRoot func() bool
}

// NewBrew returns the Homebrew helper for this machine.
func NewBrew(plat platform.Platform) *Brew {
	return &Brew{Path: LookupTool("brew"), Plat: plat, IsRoot: fsutil.IsElevated}
}

// Environment for every brew call: no prompts, no analytics, no colour.
var brewEnv = []string{
	"NONINTERACTIVE=1",
	"HOMEBREW_NO_ANALYTICS=1",
	"HOMEBREW_NO_ENV_HINTS=1",
	"HOMEBREW_NO_COLOR=1",
	"HOMEBREW_NO_EMOJI=1",
}

// Installed reports whether Homebrew is present.
func (b *Brew) Installed() bool { return b != nil && b.Path != "" }

// Command returns the command for "brew <args>". autoUpdate false adds
// HOMEBREW_NO_AUTO_UPDATE=1 (read-only queries must not trigger an update).
func (b *Brew) Command(ctx context.Context, autoUpdate bool, args ...string) (platform.Command, error) {
	if !b.Installed() {
		return platform.Command{}, fmt.Errorf("brew: %w", ErrToolMissing)
	}
	cmd := platform.Command{Path: b.Path, Args: args, Env: append([]string(nil), brewEnv...)}
	if !autoUpdate {
		cmd.Env = append(cmd.Env, "HOMEBREW_NO_AUTO_UPDATE=1")
	}
	if b.IsRoot == nil || b.IsRoot() {
		u, err := b.Plat.ConsoleUser(ctx)
		if err != nil {
			return platform.Command{}, err
		}
		if u == nil || u.UID == "0" || u.Name == "root" {
			return platform.Command{}, platform.ErrNoConsoleUser
		}
		cmd.AsUser = u
		// Root's working directory may not be readable by the user.
		cmd.Dir = u.Home
	}
	return cmd, nil
}

// Query asks Homebrew whether a formula or cask is installed.
func (b *Brew) Query(ctx context.Context, id string) (PackageState, error) {
	cmd, err := b.Command(ctx, false, "list", "--versions", "--", id)
	if err != nil {
		return PackageState{}, err
	}
	res, err := Output(ctx, b.Plat, queryTimeout, cmd)
	if err != nil {
		return PackageState{}, err
	}
	if res.ExitCode != 0 {
		return PackageState{}, nil
	}
	return ParseBrewQuery(res.Stdout), nil
}
