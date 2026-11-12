// Package pkginstall implements the "package.install" and
// "package.uninstall" job kinds (PROTOCOL.md section 6.2): custom installer
// packages uploaded to the server.
//
// package.install downloads the blob over the pinned channel into the
// agent's root-only temporary directory, verifies size and SHA-256 (the
// values come from the signed job) BEFORE anything is executed, and then
// installs silently by type: msi and exe on Windows, pkg and dmg on macOS,
// deb and rpm on Linux. A hash or size mismatch is "rejected" and nothing
// runs. Detection rules decide "is it installed, which version" before
// (skip when already installed) and after the installation.
//
// Installer arguments are never logged and never echoed to the job output
// (they may contain licence keys); the log carries the file's SHA-256.
package pkginstall

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

// Package types.
const (
	TypeMSI = "msi"
	TypeEXE = "exe"
	TypePKG = "pkg"
	TypeDMG = "dmg"
	TypeDEB = "deb"
	TypeRPM = "rpm"
)

// Input limits.
const (
	MaxArgs          = 64
	MaxArgBytes      = 4096
	MaxFileNameBytes = 200
	MaxPackageBytes  = transport.MaxBlobBytes
)

// Windows Installer exit codes that mean success.
const (
	exitRebootRequired  = 3010 // ERROR_SUCCESS_REBOOT_REQUIRED
	exitRebootInitiated = 1641 // ERROR_SUCCESS_REBOOT_INITIATED
	exitUnknownProduct  = 1605 // ERROR_UNKNOWN_PRODUCT (uninstall: nothing to remove)
)

// Env is what the handlers need from the operating system. The per-OS
// defaultEnv functions fill it in; tests build their own.
type Env struct {
	// OSName is used in "not supported" messages.
	OSName string
	// Types are the installer types of this operating system.
	Types []string
	// Detections are the detection rule types available on this OS.
	Detections []string
	// UninstallTools are the tools an uninstallCommand may name without a path.
	UninstallTools []string
	// Lookup resolves a tool to its absolute path ("" if not installed).
	Lookup software.Lookup
	// Brew builds Homebrew commands that never run as root (may be nil).
	Brew *software.Brew
	// AppDirs are the application folders: "app" detection searches them and
	// a .app from a disk image is copied into the first one.
	AppDirs []string
	// FileVersion returns the version of a file ("" if it has none); nil on
	// systems where files carry no version resource.
	FileVersion func(path string) string
	// Registry evaluates a registry detection rule (key below HKLM); nil
	// where there is no registry.
	Registry func(key, valueName string) (software.PackageState, error)
}

var allTypes = []string{TypeMSI, TypeEXE, TypePKG, TypeDMG, TypeDEB, TypeRPM}

// reservedNames are the DOS device names Windows resolves in any directory.
var reservedNameRe = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`)

// ValidFileName reports whether name is a plain base name that is safe to
// create inside the agent's temporary directory on every supported OS: no
// path separators, no drive or stream separator, no wildcard or control
// characters, not hidden, not an option look-alike and not a DOS device name.
func ValidFileName(name string) bool {
	if name == "" || len(name) > MaxFileNameBytes || name != strings.TrimSpace(name) {
		return false
	}
	if strings.ContainsAny(name, `/\:*?"<>|`) || hasControl(name) {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") || strings.HasSuffix(name, ".") {
		return false
	}
	return !reservedNameRe.MatchString(name)
}

func validArgs(args []string) error {
	if len(args) > MaxArgs {
		return fmt.Errorf("more than %d arguments", MaxArgs)
	}
	for i, a := range args {
		if len(a) > MaxArgBytes {
			return fmt.Errorf("argument %d exceeds %d bytes", i, MaxArgBytes)
		}
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("argument %d contains a NUL character", i)
		}
	}
	return nil
}

// ValidateInstall checks every field of a package.install spec.
func ValidateInstall(spec *protocol.PackageInstallSpec) error {
	if !protocol.ValidUUID(spec.BlobID) {
		return errors.New("blobId is not a valid id")
	}
	if !protocol.ValidSHA256Hex(spec.SHA256) {
		return errors.New("sha256 is not a lowercase hex SHA-256 digest")
	}
	if spec.SizeBytes <= 0 || spec.SizeBytes > MaxPackageBytes {
		return errors.New("sizeBytes is out of range")
	}
	if !ValidFileName(spec.FileName) {
		return errors.New("fileName must be a plain file name without path separators")
	}
	if !contains(allTypes, spec.Type) {
		return errors.New("type must be one of msi, exe, pkg, dmg, deb, rpm")
	}
	if err := validArgs(spec.InstallArgs); err != nil {
		return fmt.Errorf("installArgs: %w", err)
	}
	// Only Windows installers take free-form arguments. The other tools
	// have no per-package silent switches, and their options could only
	// weaken the installation (for example "-allowUntrusted").
	if len(spec.InstallArgs) > 0 && spec.Type != TypeMSI && spec.Type != TypeEXE {
		return fmt.Errorf("installArgs are not supported for type %s", spec.Type)
	}
	if spec.Detection != nil {
		if err := ValidateDetection(spec.Detection); err != nil {
			return err
		}
	}
	return nil
}

// InstallHandler implements package.install.
type InstallHandler struct {
	env func(plat platform.Platform) Env
}

// NewInstall returns the package.install handler for this OS.
func NewInstall() *InstallHandler { return &InstallHandler{env: defaultEnv} }

// NewInstallWithEnv returns a package.install handler with an explicit
// environment (tests).
func NewInstallWithEnv(env Env) *InstallHandler {
	return &InstallHandler{env: func(platform.Platform) Env { return env }}
}

// errorResult maps an error from detection or an installer run to a result.
func errorResult(err error) jobs.Result {
	var ue *unsupportedError
	if errors.As(err, &ue) {
		return jobs.Unsupported("%s", ue.what)
	}
	return jobs.FromError(err)
}

// verifyFile re-checks size and SHA-256 of the downloaded file on disk. The
// blob client already verified the stream; this second check makes "never
// execute an unverified package" independent of the client implementation.
func verifyFile(path string, sizeBytes int64, sha256Hex string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, sizeBytes+1))
	if err != nil {
		return err
	}
	if n != sizeBytes {
		return transport.ErrSizeMismatch
	}
	want, err := hex.DecodeString(sha256Hex)
	if err != nil || subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return transport.ErrHashMismatch
	}
	return nil
}

// localName is the name the package is stored under: the validated file
// name, with the type's extension appended when it is missing (apt and dnf
// recognise a local package by its extension).
func localName(fileName, typ string) string {
	ext := "." + typ
	if strings.HasSuffix(strings.ToLower(fileName), ext) {
		return fileName
	}
	return fileName + ext
}

func successExit(typ string, code int) bool {
	if code == 0 {
		return true
	}
	return (typ == TypeMSI || typ == TypeEXE) && (code == exitRebootRequired || code == exitRebootInitiated)
}

// Handle implements jobs.Handler.
func (h *InstallHandler) Handle(jc *jobs.JobContext) jobs.Result {
	var spec protocol.PackageInstallSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if err := ValidateInstall(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	env := h.env(jc.Platform)
	if !contains(env.Types, spec.Type) {
		return jobs.Unsupported("%s packages cannot be installed on %s", spec.Type, env.OSName)
	}
	jc.Log.Info("package install",
		slog.String("type", spec.Type),
		slog.String("file_sha256", spec.SHA256),
		slog.Int64("size_bytes", spec.SizeBytes),
		slog.Int("arg_count", len(spec.InstallArgs)),
		slog.Bool("detection", spec.Detection != nil))

	// Detection first: an already installed package is not downloaded or run again.
	if spec.Detection != nil {
		state, err := env.Detect(jc.Ctx, jc.Platform, spec.Detection)
		if err != nil {
			return errorResult(err)
		}
		if Satisfied(state, spec.Detection.MinVersion) {
			if state.Version != "" {
				fmt.Fprintf(jc.Stdout, "Already installed (version %s); nothing to do.\n", state.Version)
			} else {
				fmt.Fprintln(jc.Stdout, "Already installed; nothing to do.")
			}
			res := jobs.SucceededWith(protocol.InstallResult{Installed: true, Version: state.Version})
			res.Message = "already installed"
			return res
		}
	}

	dir, err := makeTempDir(jc.TempDir)
	if err != nil {
		return jobs.Failed("create temporary directory: %v", err)
	}
	defer func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			jc.Log.Warn("could not remove package temp directory", slog.Any("error", rerr))
		}
	}()
	file := filepath.Join(dir, localName(spec.FileName, spec.Type))

	fmt.Fprintf(jc.Stdout, "Downloading package (%d bytes, sha256 %s)\n", spec.SizeBytes, spec.SHA256)
	if jc.Blobs == nil {
		return jobs.Failed("no blob client")
	}
	err = jc.Blobs.DownloadFile(jc.Ctx, spec.BlobID, file, spec.SizeBytes, spec.SHA256)
	if err == nil {
		err = verifyFile(file, spec.SizeBytes, spec.SHA256)
	}
	if err != nil {
		_ = os.Remove(file)
		if errors.Is(err, transport.ErrHashMismatch) || errors.Is(err, transport.ErrSizeMismatch) {
			jc.Log.Warn("package rejected: content does not match the signed job", slog.Any("error", err))
			return jobs.Rejected("the downloaded package does not match the signed size and SHA-256; nothing was executed")
		}
		return jobs.Failed("download package: %v", err)
	}
	fmt.Fprintln(jc.Stdout, "Package verified.")

	run := &installRun{jc: jc, env: &env, dir: dir}
	code, err := run.install(spec.Type, file, spec.InstallArgs)
	if err != nil {
		return errorResult(err)
	}
	ok := successExit(spec.Type, code)
	result := protocol.InstallResult{Installed: ok}
	res := jobs.Result{Status: protocol.StatusSucceeded, ExitCode: &code}
	if !ok {
		res.Status = protocol.StatusFailed
		res.Message = fmt.Sprintf("installer exited with code %d", code)
	} else if code != 0 {
		res.Message = "installed; a restart is required to finish"
	}

	// Detection afterwards decides what is reported as installed.
	if spec.Detection != nil {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(jc.Ctx), 2*time.Minute)
		state, derr := env.Detect(dctx, jc.Platform, spec.Detection)
		cancel()
		switch {
		case derr != nil:
			fmt.Fprintf(jc.Stderr, "detection after install failed: %v\n", derr)
		default:
			result.Installed = state.Installed
			result.Version = state.Version
			switch {
			case !ok:
			case !state.Installed:
				res.Status = protocol.StatusFailed
				res.Message = "the installer reported success but the detection rule does not find the package"
			case !Satisfied(state, spec.Detection.MinVersion) && state.Version != "":
				res.Status = protocol.StatusFailed
				res.Message = fmt.Sprintf("installed version %s is older than the required %s", state.Version, spec.Detection.MinVersion)
			}
		}
	}
	res.Result = result
	return res
}

func makeTempDir(base string) (string, error) {
	if base != "" {
		if err := os.MkdirAll(base, 0o700); err != nil {
			return "", err
		}
	}
	return os.MkdirTemp(base, "dranzo-pkg-") // created 0700
}

// installRun carries what one installation needs.
type installRun struct {
	jc  *jobs.JobContext
	env *Env
	dir string
}

// runTool streams a tool's output to the job and returns its exit code. The
// announcement shows the tool and its fixed arguments only.
func (r *installRun) runTool(announce string, cmd platform.Command) (int, error) {
	fmt.Fprintf(r.jc.Stdout, "> %s\n", announce)
	cmd.Stdout, cmd.Stderr = r.jc.Stdout, r.jc.Stderr
	return r.jc.Platform.Run(r.jc.Ctx, cmd)
}

func (r *installRun) need(tool string) (string, error) {
	p := r.env.Lookup(tool)
	if p == "" {
		return "", unsupportedf("%s is not installed", tool)
	}
	return p, nil
}

func extraArgs(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (+%d installer arguments)", n)
}

// install runs the silent installation for the package type.
func (r *installRun) install(typ, file string, args []string) (int, error) {
	name := filepath.Base(file)
	switch typ {
	case TypeMSI:
		msiexec, err := r.need("msiexec")
		if err != nil {
			return 0, err
		}
		argv := append([]string{"/i", file, "/qn", "/norestart"}, args...)
		return r.runTool("msiexec /i "+name+" /qn /norestart"+extraArgs(len(args)), platform.Command{Path: msiexec, Args: argv, Dir: r.dir})
	case TypeEXE:
		// An EXE installer has no universal silent switch: it is run with
		// exactly the installArgs of the package definition (for example
		// "/S" or "/quiet /norestart"). Without them it may wait for input
		// until the job times out; that is the package author's choice.
		return r.runTool(name+extraArgs(len(args)), platform.Command{Path: file, Args: args, Dir: r.dir})
	case TypePKG:
		return r.installPkg(file)
	case TypeDMG:
		return r.installDMG(file)
	case TypeDEB:
		if aptGet := r.env.Lookup("apt-get"); aptGet != "" {
			return r.runTool("apt-get -y install "+name, platform.Command{
				Path: aptGet,
				Args: []string{"-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "-o", "DPkg::Lock::Timeout=120", "install", "--", file},
				Env:  []string{"DEBIAN_FRONTEND=noninteractive"},
			})
		}
		dpkg, err := r.need("dpkg")
		if err != nil {
			return 0, unsupportedf("deb packages need apt-get or dpkg, which are not installed")
		}
		return r.runTool("dpkg -i "+name, platform.Command{Path: dpkg, Args: []string{"-i", file}, Env: []string{"DEBIAN_FRONTEND=noninteractive"}})
	case TypeRPM:
		if dnf := r.env.Lookup("dnf"); dnf != "" {
			return r.runTool("dnf -y install "+name, platform.Command{Path: dnf, Args: []string{"-y", "install", "--", file}})
		}
		rpm, err := r.need("rpm")
		if err != nil {
			return 0, unsupportedf("rpm packages need dnf or rpm, which are not installed")
		}
		return r.runTool("rpm -U "+name, platform.Command{Path: rpm, Args: []string{"-U", file}})
	}
	return 0, unsupportedf("package type %s", typ)
}

func (r *installRun) installPkg(file string) (int, error) {
	installer, err := r.need("installer")
	if err != nil {
		return 0, err
	}
	return r.runTool("installer -pkg "+filepath.Base(file)+" -target /", platform.Command{Path: installer, Args: []string{"-pkg", file, "-target", "/"}})
}

// installDMG attaches the disk image read-only and without showing it in
// Finder, installs the single .pkg at its top level or copies the single
// .app into the application folder, and always detaches the image again.
func (r *installRun) installDMG(file string) (code int, err error) {
	hdiutil, err := r.need("hdiutil")
	if err != nil {
		return 0, err
	}
	mount := filepath.Join(r.dir, "mnt")
	if err := os.Mkdir(mount, 0o700); err != nil {
		return 0, err
	}
	// Stdin stays closed: an image with an embedded licence agreement fails
	// instead of waiting for an answer nobody can give.
	code, err = r.runTool("hdiutil attach -nobrowse -readonly "+filepath.Base(file), platform.Command{
		Path: hdiutil,
		Args: []string{"attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount, file},
	})
	if err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, fmt.Errorf("the disk image could not be attached (hdiutil exited with code %d)", code)
	}
	defer func() {
		// Detach even when the job was cancelled or timed out.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(r.jc.Ctx), 2*time.Minute)
		defer cancel()
		dcode, derr := r.jc.Platform.Run(dctx, platform.Command{Path: hdiutil, Args: []string{"detach", mount, "-force"}, Stdout: r.jc.Stdout, Stderr: r.jc.Stderr})
		if derr != nil || dcode != 0 {
			r.jc.Log.Warn("could not detach disk image", slog.Int("exit_code", dcode), slog.Any("error", derr))
		}
	}()

	entries, rerr := os.ReadDir(mount)
	if rerr != nil {
		return 0, fmt.Errorf("read disk image: %w", rerr)
	}
	var pkgs, apps []string
	for _, e := range entries {
		name := e.Name()
		lower := strings.ToLower(name)
		if strings.HasPrefix(name, ".") || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		switch {
		case (strings.HasSuffix(lower, ".pkg") || strings.HasSuffix(lower, ".mpkg")) && !strings.HasPrefix(name, "-"):
			pkgs = append(pkgs, name)
		case strings.HasSuffix(lower, ".app") && e.IsDir() && !strings.HasPrefix(name, "-"):
			apps = append(apps, name)
		}
	}
	switch {
	case len(pkgs) == 1:
		return r.installPkg(filepath.Join(mount, pkgs[0]))
	case len(pkgs) == 0 && len(apps) == 1:
		return r.copyApp(filepath.Join(mount, apps[0]))
	}
	return 0, fmt.Errorf("the disk image must contain exactly one .pkg, or no .pkg and exactly one .app, at its top level (found %d .pkg and %d .app)", len(pkgs), len(apps))
}

// copyApp copies an application bundle into the application folder with
// ditto (which preserves signatures, extended attributes and resource
// forks), replacing an existing bundle of the same name only once the copy
// is complete.
func (r *installRun) copyApp(src string) (int, error) {
	if len(r.env.AppDirs) == 0 {
		return 0, unsupportedf("no application folder on %s", r.env.OSName)
	}
	ditto, err := r.need("ditto")
	if err != nil {
		return 0, err
	}
	name := filepath.Base(src)
	dest := filepath.Join(r.env.AppDirs[0], name)
	staged := filepath.Join(r.env.AppDirs[0], ".dranzo-new-"+name)
	old := filepath.Join(r.env.AppDirs[0], ".dranzo-old-"+name)
	_ = os.RemoveAll(staged)
	code, err := r.runTool("ditto "+name+" "+dest, platform.Command{Path: ditto, Args: []string{src, staged}})
	if err != nil || code != 0 {
		_ = os.RemoveAll(staged)
		return code, err
	}
	_ = os.RemoveAll(old)
	replaced := false
	if _, serr := os.Lstat(dest); serr == nil {
		if err := os.Rename(dest, old); err != nil {
			_ = os.RemoveAll(staged)
			return 0, fmt.Errorf("replace existing application: %w", err)
		}
		replaced = true
	}
	if err := os.Rename(staged, dest); err != nil {
		if replaced {
			_ = os.Rename(old, dest)
		}
		_ = os.RemoveAll(staged)
		return 0, fmt.Errorf("install application: %w", err)
	}
	if replaced {
		_ = os.RemoveAll(old)
	}
	fmt.Fprintf(r.jc.Stdout, "Installed %s\n", dest)
	return 0, nil
}
