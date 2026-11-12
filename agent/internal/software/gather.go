package software

import (
	"context"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// The gather functions below only run tools through the platform handle, so
// they are OS-independent code and are tested with a fake platform on every
// OS. Which of them runs is decided by the per-OS gatherOS function.

// Lookup resolves a tool name to its absolute path ("" if not installed).
type Lookup func(name string) string

// Timeouts and bounds of the inventory tools.
const (
	listTimeout = 2 * time.Minute
	// maxPkgInfo bounds the number of "pkgutil --pkg-info" calls of one
	// collection; receipts beyond it are reported without a version.
	maxPkgInfo = 500
	// pkgInfoBudget bounds the total time spent on those calls.
	pkgInfoBudget = 60 * time.Second
)

// runList runs a listing tool and returns its stdout; ok is false when the
// tool could not be run or failed.
func runList(ctx context.Context, r Runner, cmd platform.Command) (string, bool) {
	res, err := Output(ctx, r, listTimeout, cmd)
	if err != nil || res.ExitCode != 0 {
		return res.Stdout, false
	}
	return res.Stdout, true
}

// GatherLinux collects dpkg and/or rpm packages plus snaps and flatpaks.
func GatherLinux(ctx context.Context, plat platform.Platform, lookup Lookup) (items []protocol.SoftwareItem, unsupported []string) {
	dpkgQuery, rpm := lookup("dpkg-query"), lookup("rpm")
	if dpkgQuery != "" {
		out, ok := runList(ctx, plat, platform.Command{Path: dpkgQuery, Args: []string{"-W", "-f=" + DpkgQueryFormat}})
		if ok {
			items = append(items, ParseDpkgQuery(out)...)
		} else {
			unsupported = append(unsupported, protocol.SourceDpkg)
		}
	}
	if rpm != "" {
		out, ok := runList(ctx, plat, platform.Command{Path: rpm, Args: []string{"-qa", "--qf", RpmQueryFormat}})
		if ok {
			items = append(items, ParseRpmQa(out)...)
		} else {
			unsupported = append(unsupported, protocol.SourceRPM)
		}
	}
	if dpkgQuery == "" && rpm == "" {
		// Neither of the two supported package databases exists.
		unsupported = append(unsupported, protocol.SourceDpkg, protocol.SourceRPM)
	}
	if snap := lookup("snap"); snap != "" {
		// "snap list" fails when snapd is not running; that is "no snaps".
		if out, ok := runList(ctx, plat, platform.Command{Path: snap, Args: []string{"list"}}); ok {
			items = append(items, ParseSnapList(out)...)
		} else {
			unsupported = append(unsupported, protocol.SourceSnap)
		}
	}
	if flatpak := lookup("flatpak"); flatpak != "" {
		if out, ok := runList(ctx, plat, platform.Command{Path: flatpak, Args: []string{"list", "--app", "--columns=" + FlatpakColumns}}); ok {
			items = append(items, ParseFlatpakList(out)...)
		} else {
			unsupported = append(unsupported, protocol.SourceFlatpak)
		}
	}
	return items, unsupported
}

// GatherPkgutil lists the installer receipts and, within maxPkgInfo calls and
// pkgInfoBudget, their versions.
func GatherPkgutil(ctx context.Context, r Runner, pkgutil string) ([]protocol.SoftwareItem, bool) {
	out, ok := runList(ctx, r, platform.Command{Path: pkgutil, Args: []string{"--pkgs"}})
	if !ok {
		return nil, false
	}
	ids := ParsePkgutilPkgs(out)
	deadline := time.Now().Add(pkgInfoBudget)
	items := make([]protocol.SoftwareItem, 0, len(ids))
	for i, id := range ids {
		var info PkgutilInfo
		if i < maxPkgInfo && time.Now().Before(deadline) && ctx.Err() == nil {
			if res, err := Output(ctx, r, 15*time.Second, platform.Command{Path: pkgutil, Args: []string{"--pkg-info", id}}); err == nil && res.ExitCode == 0 {
				info = ParsePkgutilInfo(res.Stdout)
			}
		}
		items = append(items, PkgutilItem(id, info))
	}
	return items, true
}

// GatherBrew lists Homebrew formulae and casks, as the console user.
func GatherBrew(ctx context.Context, brew *Brew) ([]protocol.SoftwareItem, bool) {
	var items []protocol.SoftwareItem
	for _, kind := range []string{"--formula", "--cask"} {
		cmd, err := brew.Command(ctx, false, "list", kind, "--versions")
		if err != nil {
			return nil, false
		}
		out, ok := runList(ctx, brew.Plat, cmd)
		if !ok {
			return nil, false
		}
		items = append(items, ParseBrewVersions(out)...)
	}
	return items, true
}

// GatherDarwin collects application bundles, installer receipts and Homebrew
// packages. Homebrew is optional software: when it is not installed nothing
// is reported for it; when it is installed but cannot be queried (nobody is
// logged in, and brew must never run as root) "brew" is listed as unsupported.
func GatherDarwin(ctx context.Context, plat platform.Platform, lookup Lookup, brew *Brew, appDirs []string) (items []protocol.SoftwareItem, unsupported []string) {
	items = append(items, AppItems(ctx, plat, lookup("plutil"), FindAppBundles(appDirs))...)
	if pkgutil := lookup("pkgutil"); pkgutil == "" {
		unsupported = append(unsupported, protocol.SourcePkgutil)
	} else if pk, ok := GatherPkgutil(ctx, plat, pkgutil); ok {
		items = append(items, pk...)
	} else {
		unsupported = append(unsupported, protocol.SourcePkgutil)
	}
	if brew.Installed() {
		if b, ok := GatherBrew(ctx, brew); ok {
			items = append(items, b...)
		} else {
			unsupported = append(unsupported, protocol.SourceBrew)
		}
	}
	return items, unsupported
}

// GatherWinget lists the packages winget knows about. ok is false when
// winget is missing or unusable in the service's context (winget is a
// per-user tool and is often unavailable to LocalSystem).
func GatherWinget(ctx context.Context, r Runner, winget string) ([]protocol.SoftwareItem, bool) {
	if winget == "" {
		return nil, false
	}
	res, err := Output(ctx, r, listTimeout, platform.Command{
		Path: winget,
		Args: []string{"list", "--accept-source-agreements", "--disable-interactivity"},
	})
	if err != nil || res.ExitCode != 0 {
		return nil, false
	}
	rows := ParseWingetTable(res.Stdout)
	if len(rows) == 0 {
		// A machine always has some installed program; no parsable table
		// means winget printed an error instead of a list.
		return nil, false
	}
	return WingetItems(rows), true
}
