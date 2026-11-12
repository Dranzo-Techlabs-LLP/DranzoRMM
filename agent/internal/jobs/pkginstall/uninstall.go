package pkginstall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// productCodeRe is a Windows Installer product code: a braced GUID.
var productCodeRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// bareToolRe is a tool named without a path.
var bareToolRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateUninstall checks every field of a package.uninstall spec.
func ValidateUninstall(spec *protocol.PackageUninstallSpec) error {
	if !contains(allTypes, spec.Type) {
		return errors.New("type must be one of msi, exe, pkg, dmg, deb, rpm")
	}
	if spec.ProductCode != "" {
		if spec.Type != TypeMSI {
			return errors.New("productCode applies to type msi only")
		}
		if !productCodeRe.MatchString(spec.ProductCode) {
			return errors.New("productCode must be a GUID in braces")
		}
	}
	if err := validArgs(spec.UninstallCommand); err != nil {
		return fmt.Errorf("uninstallCommand: %w", err)
	}
	if spec.ProductCode == "" {
		if len(spec.UninstallCommand) == 0 || spec.UninstallCommand[0] == "" {
			return errors.New("uninstallCommand is required (or productCode for type msi)")
		}
		prog := spec.UninstallCommand[0]
		if hasControl(prog) {
			return errors.New("uninstallCommand[0] contains control characters")
		}
		if !filepath.IsAbs(prog) && !bareToolRe.MatchString(prog) {
			return errors.New("uninstallCommand[0] must be an absolute path or the bare name of a known tool")
		}
	}
	if spec.Detection != nil {
		if err := ValidateDetection(spec.Detection); err != nil {
			return err
		}
	}
	return nil
}

// UninstallHandler implements package.uninstall.
type UninstallHandler struct {
	env func(plat platform.Platform) Env
}

// NewUninstall returns the package.uninstall handler for this OS.
func NewUninstall() *UninstallHandler { return &UninstallHandler{env: defaultEnv} }

// NewUninstallWithEnv returns a package.uninstall handler with an explicit
// environment (tests).
func NewUninstallWithEnv(env Env) *UninstallHandler {
	return &UninstallHandler{env: func(platform.Platform) Env { return env }}
}

type rejectedError struct{ what string }

func (e *rejectedError) Error() string { return e.what }

func isBrew(prog string) bool {
	base := strings.ToLower(filepath.Base(prog))
	return base == "brew" || base == "brew.exe"
}

// command builds the uninstall command: msiexec /x for a product code,
// otherwise the validated uninstallCommand argv. The program is an absolute
// path to an existing file or one of the OS's well-known tools, resolved in
// trusted directories; Homebrew is always run as the console user.
func (h *UninstallHandler) command(ctx context.Context, env *Env, spec *protocol.PackageUninstallSpec) (platform.Command, string, error) {
	if spec.ProductCode != "" {
		msiexec := env.Lookup("msiexec")
		if msiexec == "" {
			return platform.Command{}, "", unsupportedf("msiexec is not installed")
		}
		return platform.Command{Path: msiexec, Args: []string{"/x", spec.ProductCode, "/qn", "/norestart"}},
			"msiexec /x " + spec.ProductCode + " /qn /norestart", nil
	}
	prog, args := spec.UninstallCommand[0], spec.UninstallCommand[1:]
	announce := filepath.Base(prog) + extraArgs(len(args))
	if filepath.IsAbs(prog) {
		prog = filepath.Clean(prog)
		if isBrew(prog) {
			return platform.Command{}, "", &rejectedError{what: "Homebrew must be named as the bare tool brew so that it runs as the console user"}
		}
		fi, err := os.Stat(prog)
		if err != nil || !fi.Mode().IsRegular() {
			return platform.Command{}, "", fmt.Errorf("uninstall program %s does not exist", filepath.Base(prog))
		}
		return platform.Command{Path: prog, Args: args}, announce, nil
	}
	name := strings.TrimSuffix(strings.ToLower(prog), ".exe")
	if !contains(env.UninstallTools, name) {
		return platform.Command{}, "", &rejectedError{what: fmt.Sprintf("uninstallCommand[0] %q is neither an absolute path nor a known tool on %s (%s)", prog, env.OSName, strings.Join(env.UninstallTools, ", "))}
	}
	if name == "brew" {
		if !env.Brew.Installed() {
			return platform.Command{}, "", unsupportedf("Homebrew is not installed")
		}
		cmd, err := env.Brew.Command(ctx, false, args...)
		return cmd, announce, err
	}
	path := env.Lookup(name)
	if path == "" {
		return platform.Command{}, "", unsupportedf("%s is not installed", name)
	}
	return platform.Command{Path: path, Args: args}, announce, nil
}

// Handle implements jobs.Handler.
func (h *UninstallHandler) Handle(jc *jobs.JobContext) jobs.Result {
	var spec protocol.PackageUninstallSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if err := ValidateUninstall(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	env := h.env(jc.Platform)
	if !contains(env.Types, spec.Type) {
		return jobs.Unsupported("%s packages cannot be uninstalled on %s", spec.Type, env.OSName)
	}
	jc.Log.Info("package uninstall",
		slog.String("type", spec.Type),
		slog.Bool("product_code", spec.ProductCode != ""),
		slog.Int("arg_count", len(spec.UninstallCommand)),
		slog.Bool("detection", spec.Detection != nil))

	if spec.Detection != nil {
		state, err := env.Detect(jc.Ctx, jc.Platform, spec.Detection)
		if err != nil {
			return errorResult(err)
		}
		if !state.Installed {
			fmt.Fprintln(jc.Stdout, "Not installed; nothing to do.")
			res := jobs.SucceededWith(protocol.PackageUninstallResult{Installed: false})
			res.Message = "not installed"
			return res
		}
	}

	cmd, announce, err := h.command(jc.Ctx, &env, &spec)
	if err != nil {
		var re *rejectedError
		if errors.As(err, &re) {
			return jobs.Rejected("%s", re.what)
		}
		return errorResult(err)
	}
	fmt.Fprintf(jc.Stdout, "> %s\n", announce)
	cmd.Stdout, cmd.Stderr = jc.Stdout, jc.Stderr
	code, err := jc.Platform.Run(jc.Ctx, cmd)
	if err != nil {
		return errorResult(err)
	}
	ok := code == 0
	if spec.Type == TypeMSI || spec.Type == TypeEXE {
		ok = ok || code == exitRebootRequired || code == exitRebootInitiated
	}
	if spec.ProductCode != "" && code == exitUnknownProduct {
		fmt.Fprintln(jc.Stdout, "The product is not installed.")
		ok = true
	}
	// Without a detection rule the command's exit code is all there is.
	result := protocol.PackageUninstallResult{Installed: !ok}
	res := jobs.Result{Status: protocol.StatusSucceeded, ExitCode: &code}
	if !ok {
		res.Status = protocol.StatusFailed
		res.Message = fmt.Sprintf("uninstall command exited with code %d", code)
	}
	if spec.Detection != nil {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(jc.Ctx), 2*time.Minute)
		state, derr := env.Detect(dctx, jc.Platform, spec.Detection)
		cancel()
		if derr != nil {
			fmt.Fprintf(jc.Stderr, "detection after uninstall failed: %v\n", derr)
		} else {
			result.Installed = state.Installed
			if ok && state.Installed {
				res.Status = protocol.StatusFailed
				res.Message = "the uninstall command reported success but the detection rule still finds the package"
			}
		}
	}
	res.Result = result
	return res
}
