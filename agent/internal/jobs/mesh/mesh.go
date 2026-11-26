// Package mesh implements the job kinds mesh.install and mesh.uninstall
// (docs/PROTOCOL.md section 6.2): the DranzoRMM agent installs and removes
// the MeshCentral agent ("MeshAgent"), which carries the remote desktop
// stream. DranzoRMM itself never captures the screen.
//
// The MeshAgent is installed the way its vendor documents it, under its own
// name: a normal, visible service ("Mesh Agent" on Windows, "meshagent" on
// macOS and Linux) that the operating system lists and an administrator can
// remove. Nothing here renames, hides or disguises it. Consent and the
// visible "remote session active" indicator of a desktop session are the
// DranzoRMM agent's job (package session), independent of MeshCentral's own
// consent settings.
//
// NOT VERIFIED AGAINST A REAL MESHCENTRAL SERVER: the handlers were tested
// with a stand-in binary. The command line switches used (-fullinstall,
// -fulluninstall, -nodeid) and the default install locations are the ones
// documented for MeshAgent; they still have to be confirmed with a real
// MeshAgent build and server in the phase 6 integration test.
package mesh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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
	"unicode/utf8"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

// Limits and defaults.
const (
	// MaxBinaryBytes bounds the MeshAgent download (real builds are 3-8 MiB).
	MaxBinaryBytes = 256 << 20
	// MaxSettingsBytes bounds meshagent.msh (MeshCentral's is about 32 KiB,
	// mostly installer translations).
	MaxSettingsBytes = 256 << 10
	// settingsName is the MeshAgent's settings file, read from the directory
	// of the binary.
	settingsName = "meshagent.msh"
	// DirName is the directory under the agent's state directory that holds
	// the downloaded MeshAgent binary.
	DirName = "mesh"

	defaultCommandTimeout = 10 * time.Minute
	defaultNodeIDAttempts = 10
	defaultNodeIDDelay    = 3 * time.Second
	nodeIDTimeout         = 20 * time.Second
)

// MeshAgent's documented command line switches.
const (
	argInstall   = "-fullinstall"
	argUninstall = "-fulluninstall"
	argNodeID    = "-nodeid"
)

// Commander runs the MeshAgent binary. The default uses the platform's
// process runner; tests substitute their own.
type Commander interface {
	// Run executes path with args, writes the combined output to out and
	// returns the exit code.
	Run(ctx context.Context, path string, args []string, out io.Writer) (exitCode int, err error)
}

// Options configure the handlers.
type Options struct {
	// Dir is the root-only directory for the downloaded binary
	// (<state dir>/mesh).
	Dir string
	// InstalledPaths are the places where an installed MeshAgent binary is
	// looked for (nil: the documented defaults of this OS).
	InstalledPaths []string
	// Commander runs the binary (nil: the job's platform).
	Commander Commander
	// NodeIDAttempts and NodeIDDelay control how long mesh.install waits for
	// the freshly installed agent to have a node id.
	NodeIDAttempts int
	NodeIDDelay    time.Duration
	// CommandTimeout bounds one install / uninstall run.
	CommandTimeout time.Duration
	// RestartCommand restarts the installed MeshAgent service so it reads a
	// settings file written after the install (nil: this OS's default; an
	// empty slice: never restart).
	RestartCommand []string
}

func (o Options) withDefaults() Options {
	if o.InstalledPaths == nil {
		o.InstalledPaths = defaultInstalledPaths()
	}
	if o.NodeIDAttempts <= 0 {
		o.NodeIDAttempts = defaultNodeIDAttempts
	}
	if o.NodeIDDelay <= 0 {
		o.NodeIDDelay = defaultNodeIDDelay
	}
	if o.CommandTimeout <= 0 {
		o.CommandTimeout = defaultCommandTimeout
	}
	if o.RestartCommand == nil {
		o.RestartCommand = defaultRestartCommand()
	}
	return o
}

// platformCommander runs commands through platform.Run (process-tree kill on
// cancellation, never through a shell).
type platformCommander struct{ plat platform.Platform }

func (c platformCommander) Run(ctx context.Context, path string, args []string, out io.Writer) (int, error) {
	return c.plat.Run(ctx, platform.Command{Path: path, Args: args, Dir: filepath.Dir(path), Stdout: out, Stderr: out})
}

func (o Options) commander(jc *jobs.JobContext) Commander {
	if o.Commander != nil {
		return o.Commander
	}
	plat := jc.Platform
	if plat == nil {
		plat = platform.New()
	}
	return platformCommander{plat: plat}
}

var fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ ()-]{0,127}$`)

// ValidateInstall checks every field of a mesh.install spec.
func ValidateInstall(spec *protocol.MeshInstallSpec) error {
	if !protocol.ValidUUID(spec.BlobID) {
		return errors.New("invalid blobId")
	}
	if !protocol.ValidSHA256Hex(spec.SHA256) {
		return errors.New("invalid sha256")
	}
	if spec.SizeBytes <= 0 || spec.SizeBytes > MaxBinaryBytes {
		return fmt.Errorf("sizeBytes must be between 1 and %d", int64(MaxBinaryBytes))
	}
	// The name is informational only (it is logged); the binary is always
	// stored under a fixed name, so it can never steer where the file lands.
	if !fileNamePattern.MatchString(spec.FileName) {
		return errors.New("invalid fileName")
	}
	if spec.MeshSettings != "" && !ValidSettings(spec.MeshSettings) {
		return errors.New("invalid meshSettings")
	}
	return nil
}

// ValidSettings reports whether s is a usable meshagent.msh: text that names
// the server (MeshServer=wss://... or local) and the device group
// (MeshID=0x...).
func ValidSettings(s string) bool {
	if len(s) > MaxSettingsBytes || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return false
	}
	var server, group bool
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "MeshServer=wss://"), line == "MeshServer=local":
			server = true
		case strings.HasPrefix(line, "MeshID=0x") && len(line) > len("MeshID=0x"):
			group = true
		}
	}
	return server && group
}

var (
	nodeIDBase64 = regexp.MustCompile(`^[A-Za-z0-9@$]{64}$`)
	nodeIDHex    = regexp.MustCompile(`^[0-9A-Fa-f]{96}$`)
)

// ParseNodeID extracts the node id from the output of "meshagent -nodeid".
// MeshCentral identifies a node by the SHA-384 of its public key, written as
// base64 with '@' for '+' and '$' for '/' (64 characters); a 96 digit
// hexadecimal form is accepted too. It returns "" when the output holds no id.
func ParseNodeID(output string) string {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		line = strings.TrimPrefix(line, "node//")
		switch {
		case nodeIDBase64.MatchString(line):
			return line
		case nodeIDHex.MatchString(line):
			raw, err := hex.DecodeString(line)
			if err != nil {
				continue
			}
			return strings.NewReplacer("+", "@", "/", "$").Replace(base64.StdEncoding.EncodeToString(raw))
		}
	}
	return ""
}

// NodeID formats the MeshCentral node id "node/<domain>/<id>". The agent
// does not know the MeshCentral domain; the default domain is the empty one.
func NodeID(id string) string {
	if id == "" {
		return ""
	}
	return "node//" + id
}

func (o Options) binaryPath() string { return filepath.Join(o.Dir, binaryName) }

// installedBinary returns the installed MeshAgent binary, or "".
func (o Options) installedBinary() string {
	for _, p := range o.InstalledPaths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func logger(jc *jobs.JobContext) *slog.Logger {
	if jc.Log != nil {
		return jc.Log
	}
	return slog.New(slog.DiscardHandler)
}

func jobOutput(jc *jobs.JobContext) io.Writer {
	if jc.Stdout != nil {
		return jc.Stdout
	}
	return io.Discard
}

// Install returns the handler of mesh.install.
func Install(opts Options) jobs.Handler {
	opts = opts.withDefaults()
	return jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result { return opts.install(jc) })
}

func (o Options) install(jc *jobs.JobContext) jobs.Result {
	var spec protocol.MeshInstallSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if err := ValidateInstall(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if o.Dir == "" || jc.Blobs == nil {
		return jobs.Failed("mesh.install is not configured")
	}
	log := logger(jc)
	log.Info("mesh.install", slog.String("file_name", spec.FileName), slog.String("sha256", spec.SHA256), slog.Int64("size_bytes", spec.SizeBytes))

	// 1. Download into the root-only directory. Nothing is executed before
	// size and SHA-256 (both from the signed command) have been verified.
	if err := fsutil.EnsurePrivateDir(o.Dir); err != nil {
		return jobs.Failed("prepare directory: %v", err)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return jobs.Failed("cannot create a temporary file name")
	}
	tmp := filepath.Join(o.Dir, "download-"+hex.EncodeToString(rnd[:])+".tmp")
	defer func() { _ = os.Remove(tmp) }()
	if err := jc.Blobs.DownloadFile(jc.Ctx, spec.BlobID, tmp, spec.SizeBytes, spec.SHA256); err != nil {
		if errors.Is(err, transport.ErrHashMismatch) || errors.Is(err, transport.ErrSizeMismatch) {
			return jobs.Rejected("download refused: %v", err)
		}
		return jobs.Failed("download failed: %v", err)
	}
	if err := makeExecutable(tmp); err != nil {
		return jobs.Failed("prepare binary: %v", err)
	}
	binary := o.binaryPath()
	if err := os.Rename(tmp, binary); err != nil {
		return jobs.Failed("store binary: %v", err)
	}
	// The settings file goes next to the binary, where the MeshAgent reads it
	// during the install (macOS and Linux; Windows builds carry it inside).
	if spec.MeshSettings != "" {
		if err := os.WriteFile(filepath.Join(o.Dir, settingsName), []byte(spec.MeshSettings), 0o600); err != nil {
			return jobs.Failed("store settings: %v", err)
		}
	}

	// 2. The vendor's documented silent install. It registers the MeshAgent
	// as a regular service under its own name.
	run := o.commander(jc)
	ictx, cancel := context.WithTimeout(jc.Ctx, o.CommandTimeout)
	code, err := run.Run(ictx, binary, []string{argInstall}, jobOutput(jc))
	cancel()
	if err != nil {
		return jobs.Result{Status: protocol.StatusFailed, Message: fmt.Sprintf("meshagent %s: %v", argInstall, err), Result: protocol.MeshResult{Installed: false}}
	}
	if code != 0 {
		return jobs.Result{Status: protocol.StatusFailed, ExitCode: &code, Message: fmt.Sprintf("meshagent %s: exit code %d", argInstall, code), Result: protocol.MeshResult{Installed: false}}
	}
	if spec.MeshSettings != "" {
		if err := o.ensureInstalledSettings(jc, run, spec.MeshSettings); err != nil {
			return jobs.Result{Status: protocol.StatusFailed, ExitCode: &code, Message: err.Error(), Result: protocol.MeshResult{Installed: true}}
		}
	}

	// 3. The node id, from the installed copy (it owns the agent's identity).
	// A fresh agent creates its identity when its service first starts, so
	// this is retried for a while.
	id := o.nodeID(jc, run)
	res := jobs.SucceededWith(protocol.MeshResult{Installed: true, MeshNodeID: NodeID(id)})
	res.ExitCode = &code
	if id == "" {
		res.Message = "MeshAgent installed; its node id could not be determined yet"
		log.Warn("mesh.install: node id not available")
	}
	return res
}

// ensureInstalledSettings makes sure the installed MeshAgent has its settings
// file. Without one it runs but never connects (macOS field test 2026-11-26:
// "-fullinstall" left no meshagent.msh and an empty meshagent.db). If the
// file is missing it is written and the service restarted to read it.
func (o Options) ensureInstalledSettings(jc *jobs.JobContext, run Commander, settings string) error {
	installed := o.installedBinary()
	if installed == "" {
		return errors.New("MeshAgent installed, but its install location was not found")
	}
	dest := filepath.Join(filepath.Dir(installed), settingsName)
	if current, err := os.ReadFile(dest); err == nil && ValidSettings(string(current)) {
		return nil
	}
	logger(jc).Info("mesh.install: writing the MeshAgent settings file", slog.String("path", dest))
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, []byte(settings), 0o644); err != nil { //nolint:gosec // G306: same mode MeshAgent gives its own settings file; nothing secret in it
		return fmt.Errorf("write MeshAgent settings: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write MeshAgent settings: %w", err)
	}
	if len(o.RestartCommand) == 0 {
		return nil
	}
	rctx, cancel := context.WithTimeout(jc.Ctx, nodeIDTimeout)
	defer cancel()
	code, err := run.Run(rctx, o.RestartCommand[0], o.RestartCommand[1:], jobOutput(jc))
	if err != nil {
		return fmt.Errorf("restart MeshAgent: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("restart MeshAgent: exit code %d", code)
	}
	return nil
}

func (o Options) nodeID(jc *jobs.JobContext, run Commander) string {
	for attempt := 0; attempt < o.NodeIDAttempts; attempt++ {
		if attempt > 0 {
			t := time.NewTimer(o.NodeIDDelay)
			select {
			case <-jc.Ctx.Done():
				t.Stop()
				return ""
			case <-t.C:
			}
		}
		installed := o.installedBinary()
		if installed == "" {
			continue
		}
		var out limitedBuffer
		nctx, cancel := context.WithTimeout(jc.Ctx, nodeIDTimeout)
		code, err := run.Run(nctx, installed, []string{argNodeID}, &out)
		cancel()
		if err != nil || code != 0 {
			continue
		}
		if id := ParseNodeID(out.String()); id != "" {
			return id
		}
	}
	return ""
}

// Uninstall returns the handler of mesh.uninstall.
func Uninstall(opts Options) jobs.Handler {
	opts = opts.withDefaults()
	return jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result { return opts.uninstall(jc) })
}

func (o Options) uninstall(jc *jobs.JobContext) jobs.Result {
	if o.Dir == "" {
		return jobs.Failed("mesh.uninstall is not configured")
	}
	logger(jc).Info("mesh.uninstall")
	binary := o.installedBinary()
	if binary == "" {
		// An install that did not finish may have left only our copy.
		if fi, err := os.Stat(o.binaryPath()); err == nil && fi.Mode().IsRegular() {
			binary = o.binaryPath()
		}
	}
	if binary == "" {
		res := jobs.SucceededWith(protocol.MeshResult{Installed: false})
		res.Message = "MeshAgent is not installed"
		return res
	}
	uctx, cancel := context.WithTimeout(jc.Ctx, o.CommandTimeout)
	code, err := o.commander(jc).Run(uctx, binary, []string{argUninstall}, jobOutput(jc))
	cancel()
	stillThere := o.installedBinary() != ""
	if err != nil {
		return jobs.Result{Status: protocol.StatusFailed, Message: fmt.Sprintf("meshagent %s: %v", argUninstall, err), Result: protocol.MeshResult{Installed: stillThere}}
	}
	if code != 0 {
		return jobs.Result{Status: protocol.StatusFailed, ExitCode: &code, Message: fmt.Sprintf("meshagent %s: exit code %d", argUninstall, code), Result: protocol.MeshResult{Installed: stillThere}}
	}
	_ = os.Remove(o.binaryPath())
	_ = os.Remove(filepath.Join(o.Dir, settingsName))
	res := jobs.SucceededWith(protocol.MeshResult{Installed: false})
	res.ExitCode = &code
	return res
}

// limitedBuffer keeps at most 64 KiB of command output.
type limitedBuffer struct{ b bytes.Buffer }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := 64<<10 - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.b.String() }
