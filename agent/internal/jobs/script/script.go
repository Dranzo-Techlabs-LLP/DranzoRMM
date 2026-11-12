// Package script implements the "script" job kind (PROTOCOL.md section 6.2):
// it writes the script body to a protected temporary file and runs the
// interpreter with an argv array, as the system or as the console user.
//
// The body, arguments and environment values are never logged; the log line
// carries the SHA-256 of the body instead.
package script

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Input limits.
const (
	MaxBodyBytes     = 1536 << 10
	MaxArgs          = 64
	MaxArgBytes      = 8192
	MaxEnvVars       = 64
	MaxEnvValueBytes = 32 << 10
)

// interpreter describes how one language is run on this OS.
type interpreter struct {
	// path is the absolute path of the interpreter binary.
	path string
	// prefix are the arguments placed before the script path.
	prefix []string
	// ext is the file extension of the script file (including the dot).
	ext string
	// bom writes a UTF-8 byte order mark first (Windows PowerShell 5.1 needs
	// it to read a UTF-8 script correctly).
	bom bool
	// checkArgs optionally validates the user arguments for this interpreter.
	checkArgs func(args []string) error
}

// unsupportedError marks a language (or option) the OS cannot run.
type unsupportedError struct{ what string }

func (e *unsupportedError) Error() string { return e.what }

func unsupportedf(format string, args ...any) error {
	return &unsupportedError{what: fmt.Sprintf(format, args...)}
}

// Handler is the jobs.Handler for the "script" kind.
type Handler struct{}

// New returns the script handler.
func New() Handler { return Handler{} }

// Validate checks every field of the spec. It returns a message suitable for
// a "rejected" result.
func Validate(spec *protocol.ScriptSpec) error {
	switch spec.Language {
	case protocol.LangPowerShell, protocol.LangCmd, protocol.LangBash, protocol.LangZsh, protocol.LangSh, protocol.LangPython:
	default:
		return errors.New("language must be one of powershell, cmd, bash, zsh, sh, python")
	}
	if spec.Body == "" {
		return errors.New("body is empty")
	}
	if len(spec.Body) > MaxBodyBytes {
		return fmt.Errorf("body exceeds %d bytes", MaxBodyBytes)
	}
	if strings.ContainsRune(spec.Body, 0) {
		return errors.New("body contains a NUL character")
	}
	if len(spec.Args) > MaxArgs {
		return fmt.Errorf("more than %d arguments", MaxArgs)
	}
	for i, a := range spec.Args {
		if len(a) > MaxArgBytes {
			return fmt.Errorf("argument %d exceeds %d bytes", i, MaxArgBytes)
		}
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("argument %d contains a NUL character", i)
		}
	}
	if len(spec.Env) > MaxEnvVars {
		return fmt.Errorf("more than %d environment variables", MaxEnvVars)
	}
	for k, v := range spec.Env {
		if !protocol.ValidEnvName(k) {
			return errors.New("invalid environment variable name")
		}
		if len(v) > MaxEnvValueBytes {
			return fmt.Errorf("environment variable %s exceeds %d bytes", k, MaxEnvValueBytes)
		}
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("environment variable %s contains a NUL character", k)
		}
	}
	switch spec.RunAs {
	case "":
		spec.RunAs = protocol.RunAsSystem
	case protocol.RunAsSystem, protocol.RunAsUser:
	default:
		return errors.New("runAs must be system or user")
	}
	if spec.RequireSignedPowerShell && spec.Language != protocol.LangPowerShell {
		return errors.New("requireSignedPowerShell applies to powershell scripts only")
	}
	return nil
}

// Handle implements jobs.Handler.
func (Handler) Handle(jc *jobs.JobContext) jobs.Result {
	var spec protocol.ScriptSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if err := Validate(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	sum := sha256.Sum256([]byte(spec.Body))
	jc.Log.Info("script job",
		slog.String("language", spec.Language),
		slog.String("run_as", spec.RunAs),
		slog.String("script_sha256", hex.EncodeToString(sum[:])),
		slog.Int("script_bytes", len(spec.Body)),
		slog.Int("arg_count", len(spec.Args)),
		slog.Bool("require_signed", spec.RequireSignedPowerShell))

	interp, err := resolveInterpreter(spec.Language, spec.RequireSignedPowerShell)
	if err != nil {
		var ue *unsupportedError
		if errors.As(err, &ue) {
			return jobs.Unsupported("%s", ue.what)
		}
		return jobs.Failed("%v", err)
	}
	if interp.checkArgs != nil {
		if err := interp.checkArgs(spec.Args); err != nil {
			return jobs.Rejected("%v", err)
		}
	}

	var asUser *platform.User
	if spec.RunAs == protocol.RunAsUser {
		u, err := jc.Platform.ConsoleUser(jc.Ctx)
		if err != nil {
			return jobs.FromError(err)
		}
		asUser = u
	}

	dir, scriptPath, err := writeScript(jc, interp, spec.Body, asUser)
	if dir != "" {
		defer func() {
			if rerr := os.RemoveAll(dir); rerr != nil {
				jc.Log.Warn("could not remove script temp directory", slog.Any("error", rerr))
			}
		}()
	}
	if err != nil {
		return jobs.Failed("prepare script: %v", err)
	}

	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)

	args := make([]string, 0, len(interp.prefix)+1+len(spec.Args))
	args = append(args, interp.prefix...)
	args = append(args, scriptPath)
	args = append(args, spec.Args...)

	workDir := dir
	if asUser != nil && asUser.Home != "" {
		if fi, err := os.Stat(asUser.Home); err == nil && fi.IsDir() {
			workDir = asUser.Home
		}
	}
	code, err := jc.Platform.Run(jc.Ctx, platform.Command{
		Path:   interp.path,
		Args:   args,
		Env:    env,
		Dir:    workDir,
		Stdout: jc.Stdout,
		Stderr: jc.Stderr,
		AsUser: asUser,
	})
	if err != nil {
		// Includes cancellation and timeout: the manager maps those from the context.
		return jobs.FromError(err)
	}
	return jobs.FromExitCode(code)
}

// writeScript creates the protected temp directory and the script file.
// System scripts live under the agent's root-only temp directory. A user
// script must be readable by that user, so its directory is created in the
// system temp location and handed to the user (and only that user).
func writeScript(jc *jobs.JobContext, interp *interpreter, body string, asUser *platform.User) (dir, scriptPath string, err error) {
	base := jc.TempDir
	if asUser != nil {
		base = ""
	} else if base != "" {
		if err := os.MkdirAll(base, 0o700); err != nil {
			return "", "", err
		}
	}
	dir, err = os.MkdirTemp(base, "dranzo-job-") // created 0700
	if err != nil {
		return "", "", err
	}
	scriptPath = filepath.Join(dir, "script"+interp.ext)
	f, err := os.OpenFile(scriptPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700) //nolint:gosec // owner-only; path is inside the directory just created
	if err != nil {
		return dir, "", err
	}
	if interp.bom {
		if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
			_ = f.Close()
			return dir, "", err
		}
	}
	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		return dir, "", err
	}
	if err := f.Close(); err != nil {
		return dir, "", err
	}
	if asUser != nil {
		// File first, directory last: the user gains access only once the content is complete.
		if err := jc.Platform.GrantUser(scriptPath, asUser); err != nil {
			return dir, "", fmt.Errorf("grant script to user: %w", err)
		}
		if err := jc.Platform.GrantUser(dir, asUser); err != nil {
			return dir, "", fmt.Errorf("grant script directory to user: %w", err)
		}
	}
	return dir, scriptPath, nil
}
