// Command dranzo-agent is the DranzoRMM endpoint management agent.
//
// It is a transparent IT administration tool: it installs as a normal,
// visible service, can be removed by an administrator of the device, only
// ever connects outbound to its pinned management server and executes only
// commands signed by that server.
//
//	dranzo-agent install --server https://host:8443 --token dz_enroll_... [--ca-file ca.pem --trust-file trust.json] [--data-dir D]
//	dranzo-agent run [--data-dir D] [--foreground]
//	dranzo-agent enroll [--data-dir D]
//	dranzo-agent status [--data-dir D]
//	dranzo-agent uninstall [--code XXXX] [--keep-data] [--data-dir D]
//	dranzo-agent version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/buildinfo"
	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/identity"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/svc"
	"github.com/dranzo/dranzormm/agent/internal/trust"
	"github.com/dranzo/dranzormm/agent/internal/update"
)

const usage = `DranzoRMM agent - endpoint management agent

Usage:
  dranzo-agent install   --server URL --token TOKEN [--ca-file FILE --trust-file FILE] [--data-dir DIR]
  dranzo-agent run       [--data-dir DIR] [--foreground]
  dranzo-agent enroll    [--data-dir DIR]
  dranzo-agent status    [--data-dir DIR]
  dranzo-agent uninstall [--code CODE] [--keep-data] [--data-dir DIR]
  dranzo-agent version
`

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "dranzo-agent %s (%s)\n", buildinfo.Version, platform.OSFamily)
	case "install":
		err = cmdInstall(args[1:], stdout)
	case "run":
		err = cmdRun(args[1:])
	case "enroll":
		err = cmdEnroll(args[1:], stdout)
	case "status":
		err = cmdStatus(args[1:], stdout)
	case "uninstall":
		err = cmdUninstall(args[1:], stdout)
	case "update-guard":
		// Run by the service manager before every start (systemd ExecStartPre) with the
		// *previous* binary: rolls back an update whose new binary keeps crashing before it
		// can count its own starts. Always exits 0 so it can never block the service.
		fs := flag.NewFlagSet("update-guard", flag.ContinueOnError)
		dataDir := fs.String("data-dir", "", "override the data directory")
		if fs.Parse(args[1:]) == nil {
			rolled, gerr := update.Guard(update.GuardOptions{StateDir: config.ResolvePaths(*dataDir).StateDir})
			fmt.Fprintf(stderr, "update-guard: rolled back: %v, error: %v\n", rolled, gerr)
		}
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		fmt.Fprintf(stderr, "dranzo-agent: %s\n", logging.Redact(err.Error()))
		return 1
	}
	return 0
}

var tokenRe = regexp.MustCompile(`^dz_enroll_[A-Za-z0-9._~-]{8,480}$`)

func requireElevated(action string) error {
	if !fsutil.IsElevated() {
		return fmt.Errorf("%s must be run as root (Unix) or from an elevated Administrator prompt (Windows)", action)
	}
	return nil
}

func cmdInstall(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	server := fs.String("server", "", "management server URL, e.g. https://rmm.example.com:8443")
	token := fs.String("token", "", "enrollment token (dz_enroll_...); may also be given in DRANZO_ENROLL_TOKEN")
	caFile := fs.String("ca-file", "", "PEM file with the pinned DranzoRMM CA certificate(s)")
	trustFile := fs.String("trust-file", "", "trust.json with the command signing public keys")
	dataDir := fs.String("data-dir", "", "override the data directory (development only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		*token = os.Getenv("DRANZO_ENROLL_TOKEN")
	}
	serverURL, err := config.ValidateServerURL(*server)
	if err != nil {
		return fmt.Errorf("--server: %w", err)
	}
	if !tokenRe.MatchString(*token) {
		return errors.New("--token: an enrollment token of the form dz_enroll_... is required")
	}
	if (*caFile == "") != (*trustFile == "") {
		return errors.New("--ca-file and --trust-file must be given together")
	}
	if err := requireElevated("install"); err != nil {
		return err
	}

	// Read and validate the trust anchors before touching the system.
	var (
		caPEM []byte
		keys  []protocol.CommandKey
	)
	if *caFile != "" {
		if caPEM, keys, err = trust.ReadInstallerFiles(*caFile, *trustFile); err != nil {
			return err
		}
	}

	paths := config.ResolvePaths(*dataDir)
	if err := paths.Ensure(); err != nil {
		return err
	}
	svcArgs := []string{"run"}
	if *dataDir != "" {
		svcArgs = append(svcArgs, "--data-dir", paths.StateDir)
	}
	// Register the service first: if it already exists nothing is changed and
	// no token is written to disk.
	if err := svc.Register(svcArgs); err != nil {
		return fmt.Errorf("%w\nIf the agent is already installed, run \"dranzo-agent uninstall\" first to enroll this device again", err)
	}
	replaced, err := writeInstallFiles(paths, serverURL, *token, caPEM, keys)
	if err != nil {
		// Do not leave a service behind that cannot start.
		_ = svc.Uninstall()
		return err
	}
	if err := svc.Start(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Installed and started the %q service (%s).\nServer: %s\nData directory: %s\n",
		svc.DisplayName, svc.Name(), serverURL, paths.StateDir)
	if replaced {
		fmt.Fprintln(stdout, "A device identity from an earlier installation was removed: this computer enrolls as a new device.")
	}
	return nil
}

// writeInstallFiles writes the trust anchors and bootstrap.json. An identity
// left behind by an earlier installation is removed, because "install" with a
// token always means a new enrollment (the token would otherwise be erased
// unused by the first start). It reports whether an identity was replaced.
func writeInstallFiles(paths config.Paths, serverURL, token string, caPEM []byte, keys []protocol.CommandKey) (replaced bool, err error) {
	if len(caPEM) > 0 {
		if err := trust.Install(paths.CAFile(), paths.TrustFile(), caPEM, keys); err != nil {
			return false, err
		}
	} else {
		// No files given: the anchors compiled into this binary must exist
		// (or a previous install must have left a trust store).
		defCA, err := buildinfo.CAPEM()
		if err != nil {
			return false, err
		}
		defKeys, err := buildinfo.CommandKeys()
		if err != nil {
			return false, err
		}
		if _, err := trust.LoadOrSeed(paths.CAFile(), paths.TrustFile(), defCA, defKeys); err != nil {
			return false, fmt.Errorf("%w; pass --ca-file and --trust-file", err)
		}
	}
	if fsutil.Exists(paths.KeyFile()) || fsutil.Exists(paths.CertFile()) {
		identity.NewStore(paths.KeyFile(), paths.CertFile()).Remove()
		for _, f := range []string{paths.ConfigFile(), paths.StatusFile()} {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
		}
		replaced = true
	}
	if err := config.SaveBootstrap(paths, &config.Bootstrap{ServerURL: serverURL, Token: token}); err != nil {
		return replaced, err
	}
	return replaced, nil
}

func newAgent(paths config.Paths, log *slog.Logger, asService bool) (*agentcore.Agent, error) {
	opts := agentcore.Options{
		Paths:    paths,
		Logger:   log,
		Platform: platform.New(),
		Version:  buildinfo.Version,
	}
	if asService {
		opts.SelfUninstall = func(context.Context) error {
			removeFirewallRules(paths)
			return svc.SelfUninstall(paths)
		}
	}
	agent, err := agentcore.New(opts)
	if err != nil {
		return nil, err
	}
	// Feature modules (software, patching, posture, sessions, updates) register
	// their job handlers and reporters here; see wiring.go.
	for _, wire := range features {
		if err := wire(agent); err != nil {
			return nil, err
		}
	}
	return agent, nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "override the data directory (development, containers, tests)")
	foreground := fs.Bool("foreground", false, "run in the foreground instead of under the service manager")
	debug := fs.Bool("debug", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths := config.ResolvePaths(*dataDir)
	if err := paths.Ensure(); err != nil {
		return err
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log, closer, err := logging.New(logging.Options{File: paths.LogFile(), Stderr: *foreground, Level: level})
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()

	if *foreground {
		agent, err := newAgent(paths, log, false)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return agent.Run(ctx)
	}
	return svc.Run(func(ctx context.Context) error {
		agent, err := newAgent(paths, log, true)
		if err != nil {
			return err
		}
		return agent.Run(ctx)
	}, log)
}

func cmdEnroll(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "override the data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths := config.ResolvePaths(*dataDir)
	if err := paths.Ensure(); err != nil {
		return err
	}
	log, closer, err := logging.New(logging.Options{File: paths.LogFile(), Stderr: true})
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	agent, err := newAgent(paths, log, false)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	id, err := agent.Enroll(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Enrolled. Device ID: %s\n", id)
	return nil
}

func cmdStatus(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "override the data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths := config.ResolvePaths(*dataDir)

	fmt.Fprintf(stdout, "Agent version:  %s\n", buildinfo.Version)
	fmt.Fprintf(stdout, "Service:        %s (%s)\n", svc.Status(), svc.Name())
	fmt.Fprintf(stdout, "Data directory: %s\n", paths.StateDir)

	cfg, err := config.Load(paths)
	switch {
	case err == nil:
		fmt.Fprintf(stdout, "Server:         %s\n", cfg.ServerURL)
		fmt.Fprintf(stdout, "Device ID:      %s\n", orDash(cfg.DeviceID))
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintln(stdout, "Server:         - (not enrolled)")
		fmt.Fprintln(stdout, "Device ID:      -")
	case errors.Is(err, os.ErrPermission):
		return errors.New("status needs root / Administrator rights to read the agent's protected data directory")
	default:
		return err
	}

	if id, err := identity.NewStore(paths.KeyFile(), paths.CertFile()).Load(); err == nil {
		left := time.Until(id.Leaf.NotAfter).Round(time.Hour)
		fmt.Fprintf(stdout, "Certificate:    valid until %s (%s left)\n", id.Leaf.NotAfter.UTC().Format(time.RFC3339), left)
	} else {
		fmt.Fprintln(stdout, "Certificate:    -")
	}

	st, err := config.LoadStatus(paths)
	if err != nil {
		fmt.Fprintln(stdout, "Connection:     unknown (agent has not run yet)")
		return nil
	}
	state := "disconnected"
	if st.Connected {
		state = "connected"
	}
	fmt.Fprintf(stdout, "Connection:     %s since %s (pid %d)\n", state, st.Since.Format(time.RFC3339), st.PID)
	if st.LastError != "" && !st.Connected {
		fmt.Fprintf(stdout, "Last error:     %s\n", strings.TrimSpace(st.LastError))
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cmdUninstall(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	code := fs.String("code", "", "uninstall code set by your IT provider (if one is required)")
	keepData := fs.Bool("keep-data", false, "keep the data directory (identity, configuration, logs)")
	dataDir := fs.String("data-dir", "", "override the data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireElevated("uninstall"); err != nil {
		return err
	}
	paths := config.ResolvePaths(*dataDir)
	cfg, err := config.Load(paths)
	switch {
	case err == nil:
		if err := svc.VerifyUninstallCode(*code, cfg.UninstallCode); err != nil {
			return err
		}
	case errors.Is(err, os.ErrNotExist):
		// Never enrolled: nothing to protect.
	default:
		return fmt.Errorf("read configuration: %w", err)
	}
	if err := svc.Uninstall(); err != nil {
		return err
	}
	// Rules DranzoRMM added to the host firewall go with the agent.
	removeFirewallRules(paths)
	if !*keepData {
		svc.Purge(paths)
	}
	fmt.Fprintf(stdout, "The %q service was removed.\n", svc.DisplayName)
	return nil
}
