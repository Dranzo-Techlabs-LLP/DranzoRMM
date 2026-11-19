// Package swdeploy implements the "software.install" and
// "software.uninstall" job kinds (PROTOCOL.md section 6.2): deployment
// through the operating system's package manager: winget on Windows,
// Homebrew on macOS (always as the console user, never as root), apt and dnf
// on Linux.
//
// Every server-provided value is validated before use and handed to the
// tool as one element of an argv array, after a "--" separator where the
// tool supports one; nothing is ever interpreted by a shell. The result is
// determined by asking the package manager again after the tool has run.
package swdeploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// Env is what the handler needs from the operating system. The per-OS
// defaultEnv functions fill it in; tests build their own.
type Env struct {
	// OSName is used in "not supported" messages ("Windows", "macOS", "Linux").
	OSName string
	// Managers are the package managers of this operating system.
	Managers []string
	// Lookup resolves a tool to its absolute path ("" if not installed).
	Lookup software.Lookup
	// Brew builds Homebrew commands that never run as root (nil where
	// Homebrew is not a manager of this OS).
	Brew *software.Brew
}

// Handler implements software.install or software.uninstall.
type Handler struct {
	uninstall bool
	env       func(plat platform.Platform) Env
}

// NewInstall returns the software.install handler for this OS.
func NewInstall() *Handler { return &Handler{env: defaultEnv} }

// NewUninstall returns the software.uninstall handler for this OS.
func NewUninstall() *Handler { return &Handler{uninstall: true, env: defaultEnv} }

// NewWithEnv returns a handler with an explicit environment (tests).
func NewWithEnv(uninstall bool, env Env) *Handler {
	return &Handler{uninstall: uninstall, env: func(platform.Platform) Env { return env }}
}

// ValidID reports whether s is acceptable as a packageId or version: the
// pattern of PROTOCOL.md section 6.2 and, although the pattern already
// requires an alphanumeric first character, explicitly never a leading "-"
// (it must not be read as an option by any tool).
func ValidID(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && protocol.ValidPackageID(s)
}

// Validate checks every field of the spec. On top of the protocol's general
// pattern each manager only accepts what is a package NAME for it: dnf, apt
// and Homebrew would otherwise read a URL or a path as "install this file".
func Validate(spec *protocol.SoftwareSpec) error {
	switch spec.Manager {
	case protocol.ManagerWinget, protocol.ManagerBrew, protocol.ManagerApt, protocol.ManagerDnf:
	default:
		return errors.New("manager must be one of winget, brew, apt, dnf")
	}
	if !ValidID(spec.PackageID) {
		return errors.New("packageId is not a valid package identifier")
	}
	if spec.Version != "" && (!ValidID(spec.Version) || strings.Contains(spec.Version, "/") || strings.Contains(spec.Version, "@")) {
		return errors.New("version is not a valid version string")
	}
	named := true
	switch spec.Manager {
	case protocol.ManagerApt:
		named = software.ValidAptName(spec.PackageID)
	case protocol.ManagerDnf:
		named = software.ValidRpmName(spec.PackageID)
	case protocol.ManagerBrew:
		named = software.ValidBrewName(spec.PackageID)
	case protocol.ManagerWinget:
		named = software.ValidWingetID(spec.PackageID)
	}
	if !named {
		return fmt.Errorf("packageId is not a package name for %s (URLs and file paths are not accepted)", spec.Manager)
	}
	return nil
}

// queryFunc asks the package manager for the current state of the package.
type queryFunc func(ctx context.Context) (software.PackageState, error)

// step is one tool invocation of a plan.
type step struct {
	cmd platform.Command
	// bestEffort steps (refreshing the package index) do not fail the job.
	bestEffort bool
}

// Non-interactive dpkg: keep existing configuration files, wait for a
// concurrent package operation instead of failing at once.
var aptOptions = []string{
	"-y",
	"-o", "Dpkg::Options::=--force-confdef",
	"-o", "Dpkg::Options::=--force-confold",
	"-o", "DPkg::Lock::Timeout=120",
}

var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

// plan returns the commands for the spec and the query that determines the
// result afterwards.
func (h *Handler) plan(ctx context.Context, env Env, spec *protocol.SoftwareSpec, r software.Runner) ([]step, queryFunc, error) {
	id, version := spec.PackageID, spec.Version
	need := func(tool string) (string, error) {
		p := env.Lookup(tool)
		if p == "" {
			return "", &unsupportedError{what: fmt.Sprintf("%s is not installed or not available to the agent service", tool)}
		}
		return p, nil
	}
	switch spec.Manager {
	case protocol.ManagerWinget:
		winget, err := need("winget")
		if err != nil {
			return nil, nil, err
		}
		var args []string
		if h.uninstall {
			args = []string{"uninstall", "-e", "--id", id}
		} else {
			args = []string{"install", "-e", "--id", id}
		}
		if version != "" {
			args = append(args, "--version", version)
		}
		args = append(args, "--silent")
		if !h.uninstall {
			// "uninstall" has no package agreements to accept.
			args = append(args, "--accept-package-agreements")
		}
		args = append(args, "--accept-source-agreements", "--disable-interactivity")
		query := func(ctx context.Context) (software.PackageState, error) {
			return software.QueryWinget(ctx, r, winget, id)
		}
		return []step{{cmd: platform.Command{Path: winget, Args: args}}}, query, nil

	case protocol.ManagerBrew:
		if env.Brew == nil || !env.Brew.Installed() {
			return nil, nil, &unsupportedError{what: "Homebrew is not installed"}
		}
		if version != "" {
			return nil, nil, &rejectedError{what: "Homebrew cannot install a chosen version; use a versioned formula name such as node@20 as packageId"}
		}
		verb := "install"
		if h.uninstall {
			verb = "uninstall"
		}
		cmd, err := env.Brew.Command(ctx, !h.uninstall, verb, "--", id)
		if err != nil {
			return nil, nil, err
		}
		return []step{{cmd: cmd}}, func(ctx context.Context) (software.PackageState, error) { return env.Brew.Query(ctx, id) }, nil

	case protocol.ManagerApt:
		aptGet, err := need("apt-get")
		if err != nil {
			return nil, nil, err
		}
		dpkgQuery := env.Lookup("dpkg-query")
		query := func(ctx context.Context) (software.PackageState, error) {
			return software.QueryDpkg(ctx, r, dpkgQuery, id)
		}
		if h.uninstall {
			args := append(append([]string{}, aptOptions...), "remove", "--", id)
			return []step{{cmd: platform.Command{Path: aptGet, Args: args, Env: aptEnv}}}, query, nil
		}
		target := id
		if version != "" {
			target += "=" + version
		}
		args := append(append([]string{}, aptOptions...), "install", "--", target)
		return []step{
			{cmd: platform.Command{Path: aptGet, Args: []string{"-o", "DPkg::Lock::Timeout=120", "update"}, Env: aptEnv}, bestEffort: true},
			{cmd: platform.Command{Path: aptGet, Args: args, Env: aptEnv}},
		}, query, nil

	case protocol.ManagerDnf:
		dnf, err := need("dnf")
		if err != nil {
			return nil, nil, err
		}
		rpm := env.Lookup("rpm")
		query := func(ctx context.Context) (software.PackageState, error) {
			return software.QueryRpm(ctx, r, rpm, id)
		}
		if h.uninstall {
			return []step{{cmd: platform.Command{Path: dnf, Args: []string{"-y", "remove", "--", id}}}}, query, nil
		}
		target := id
		if version != "" {
			target += "-" + version
		}
		return []step{{cmd: platform.Command{Path: dnf, Args: []string{"-y", "install", "--", target}}}}, query, nil
	}
	return nil, nil, &rejectedError{what: "unknown manager"}
}

type unsupportedError struct{ what string }

func (e *unsupportedError) Error() string { return e.what }

type rejectedError struct{ what string }

func (e *rejectedError) Error() string { return e.what }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Handle implements jobs.Handler.
func (h *Handler) Handle(jc *jobs.JobContext) jobs.Result {
	var spec protocol.SoftwareSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if err := Validate(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	env := h.env(jc.Platform)
	if !contains(env.Managers, spec.Manager) {
		return jobs.Unsupported("the %s package manager is not available on %s", spec.Manager, env.OSName)
	}
	action := "install"
	if h.uninstall {
		action = "uninstall"
	}
	jc.Log.Info("software job", slog.String("action", action), slog.String("manager", spec.Manager),
		slog.String("package_id", spec.PackageID), slog.String("version", spec.Version))

	steps, query, err := h.plan(jc.Ctx, env, &spec, jc.Platform)
	if err != nil {
		var ue *unsupportedError
		var re *rejectedError
		switch {
		case errors.As(err, &ue):
			return jobs.Unsupported("%s", ue.what)
		case errors.As(err, &re):
			return jobs.Rejected("%s", re.what)
		}
		return jobs.FromError(err)
	}

	// "Install" without a version on software that is already there must not
	// change it: winget and apt treat install as upgrade, which silently
	// replaced a user's version during the 2026-11-19 field test. Upgrades
	// belong to the patch workflow, where they are approved and scheduled.
	// If the state cannot be read, fall through to the normal install.
	if !h.uninstall && spec.Version == "" && jc.Ctx.Err() == nil {
		pctx, pcancel := context.WithTimeout(jc.Ctx, 2*time.Minute)
		before, perr := query(pctx)
		pcancel()
		if perr != nil && jc.Ctx.Err() == nil {
			fmt.Fprintf(jc.Stdout, "Could not check whether %s is already installed (%v); installing anyway.\n", spec.PackageID, perr)
		}
		if perr == nil && before.Installed {
			fmt.Fprintf(jc.Stdout, "%s is already installed (version %s); nothing was changed. Use Patches to update it.\n", spec.PackageID, displayVersion(before.Version))
			unchanged := 0
			return jobs.Result{
				Status:   protocol.StatusSucceeded,
				Message:  "already installed; not changed",
				Result:   protocol.InstallResult{Installed: true, Version: before.Version},
				ExitCode: &unchanged,
			}
		}
	}

	exit := 0
	for _, s := range steps {
		fmt.Fprintf(jc.Stdout, "> %s %s\n", toolName(s.cmd.Path), strings.Join(s.cmd.Args, " "))
		s.cmd.Stdout, s.cmd.Stderr = jc.Stdout, jc.Stderr
		s.cmd.Env = software.WithCLocale(s.cmd.Env)
		code, err := jc.Platform.Run(jc.Ctx, s.cmd)
		if err != nil {
			if s.bestEffort && jc.Ctx.Err() == nil {
				continue
			}
			return jobs.FromError(err)
		}
		if code != 0 && !s.bestEffort {
			exit = code
			break
		}
	}

	// The result is what the package manager says now, not what the tool claimed.
	qctx, cancel := context.WithTimeout(context.WithoutCancel(jc.Ctx), 2*time.Minute)
	defer cancel()
	state, qerr := query(qctx)
	if qerr != nil {
		jc.Log.Warn("package state query failed", slog.Any("error", qerr))
		fmt.Fprintf(jc.Stderr, "could not query the package state: %v\n", qerr)
		// Fall back to the tool's exit code.
		state = software.PackageState{Installed: (exit == 0) != h.uninstall}
	}
	result := protocol.InstallResult{Installed: state.Installed}
	if state.Installed {
		result.Version = state.Version
	}
	res := jobs.Result{Result: result, ExitCode: &exit}
	switch {
	case exit != 0:
		res.Status = protocol.StatusFailed
		res.Message = fmt.Sprintf("%s exited with code %d", toolName(steps[len(steps)-1].cmd.Path), exit)
	case !h.uninstall && !state.Installed:
		res.Status = protocol.StatusFailed
		res.Message = "the package manager reported success but the package is not installed"
	case h.uninstall && state.Installed:
		res.Status = protocol.StatusFailed
		res.Message = "the package manager reported success but the package is still installed"
	default:
		res.Status = protocol.StatusSucceeded
	}
	return res
}

func displayVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func toolName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(path), ".exe")
}
