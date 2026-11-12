package agentcore

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/dranzo/dranzormm/agent/internal/buildinfo"
	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/identity"
	"github.com/dranzo/dranzormm/agent/internal/inventory"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/script"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/transport"
	"github.com/dranzo/dranzormm/agent/internal/trust"
)

// ReporterInventory is the name of the built-in inventory reporter.
const ReporterInventory = "inventory"

// Options configures an Agent.
type Options struct {
	Paths    config.Paths
	Logger   *slog.Logger
	Platform platform.Platform
	Version  string
	// SelfUninstall removes the service and the agent's data. It is invoked
	// for a verified agent.uninstall job after the result was reported. Nil
	// makes agent.uninstall answer "unsupported".
	SelfUninstall func(ctx context.Context) error

	// Tunables for tests (zero values use the production defaults).
	RenewCheckInterval time.Duration
	RenewFirstCheck    time.Duration
	HelloAckTimeout    time.Duration
	Backoff            *transport.Backoff
	JobFlushInterval   time.Duration
}

// Agent is the running agent core.
type Agent struct {
	opts  Options
	log   *slog.Logger
	paths config.Paths
	plat  platform.Platform

	cfgMu sync.Mutex
	cfg   config.Config

	trust     *trust.Store
	idStore   *identity.Store
	ident     atomic.Pointer[identity.Identity]
	seq       *protocol.SeqTracker
	verifier  *protocol.Verifier
	jobs      *jobs.Manager
	collector *inventory.Collector
	client    *transport.Client
	deviceID  atomic.Value // string

	connMu      sync.Mutex
	conn        *transport.Conn
	connChanged chan struct{}

	plugMu     sync.Mutex
	sessions   SessionHandler
	updates    UpdateHandler
	helloHooks []func()

	repMu     sync.Mutex
	reporters []*reporter

	hbSeq         atomic.Uint64
	lastAck       atomic.Int64 // unix nanoseconds of the last heartbeat.ack / hello.ack
	rebootMu      sync.Mutex
	rebootCached  bool
	rebootChecked time.Time
	started       atomic.Bool
}

// New prepares an agent. Handlers, reporters and the session / update
// handlers may be registered on the result before Run is called.
func New(opts Options) (*Agent, error) {
	if opts.Logger == nil {
		opts.Logger = logging.Discard()
	}
	if opts.Platform == nil {
		opts.Platform = platform.New()
	}
	if opts.Version == "" {
		opts.Version = buildinfo.Version
	}
	a := &Agent{
		opts:        opts,
		log:         opts.Logger,
		paths:       opts.Paths,
		plat:        opts.Platform,
		seq:         protocol.NewSeqTracker(),
		connChanged: make(chan struct{}),
		idStore:     identity.NewStore(opts.Paths.KeyFile(), opts.Paths.CertFile()),
		collector:   inventory.NewCollector(opts.Platform, opts.Version),
	}
	a.deviceID.Store("")
	a.cfg.Normalize()
	a.sessions = noSessions{send: a}
	a.updates = noUpdates{send: a}
	a.jobs = jobs.NewManager(context.Background(), jobs.Options{
		Sender:        a,
		Logger:        a.log,
		Platform:      a.plat,
		Blobs:         blobAdapter{a},
		Sessions:      sessionLookup{a},
		TempDir:       opts.Paths.TempDir(),
		FlushInterval: opts.JobFlushInterval,
	})
	a.registerBuiltins()
	return a, nil
}

// Jobs returns the job manager; later packages register their kinds with
// Jobs().Register(kind, handler) before Run.
func (a *Agent) Jobs() *jobs.Manager { return a.jobs }

// Env returns the handles pluggable components need.
func (a *Agent) Env() Env {
	return Env{
		Paths:    a.paths,
		Log:      a.log,
		Platform: a.plat,
		Version:  a.opts.Version,
		Sender:   a,
		Blobs:    blobAdapter{a},
		Seq:      a.seq,
		DeviceID: a.DeviceID,
	}
}

// DeviceID returns the device id ("" before enrollment).
func (a *Agent) DeviceID() string {
	id, _ := a.deviceID.Load().(string)
	return id
}

// SetSessionHandler replaces the default (unsupported) session handler. Call before Run.
func (a *Agent) SetSessionHandler(h SessionHandler) {
	a.plugMu.Lock()
	defer a.plugMu.Unlock()
	if h != nil {
		a.sessions = h
	}
}

// SetUpdateHandler replaces the default (unsupported) update handler. Call before Run.
func (a *Agent) SetUpdateHandler(h UpdateHandler) {
	a.plugMu.Lock()
	defer a.plugMu.Unlock()
	if h != nil {
		a.updates = h
	}
}

// OnHelloAck registers a function called after every hello.ack (the update
// watchdog uses it to confirm that a new binary can reach the server).
func (a *Agent) OnHelloAck(fn func()) {
	a.plugMu.Lock()
	defer a.plugMu.Unlock()
	a.helloHooks = append(a.helloHooks, fn)
}

func (a *Agent) sessionHandler() SessionHandler {
	a.plugMu.Lock()
	defer a.plugMu.Unlock()
	return a.sessions
}

func (a *Agent) updateHandler() UpdateHandler {
	a.plugMu.Lock()
	defer a.plugMu.Unlock()
	return a.updates
}

// sessionLookup lets the job manager follow a replaced session handler.
type sessionLookup struct{ a *Agent }

func (s sessionLookup) ActiveSession(id string) (string, bool) {
	return s.a.sessionHandler().ActiveSession(id)
}

// Config returns a snapshot of the current configuration.
func (a *Agent) Config() config.Config {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	return a.cfg
}

// InventoryInterval, SoftwareInterval, PostureInterval and PatchScanInterval
// return the current (clamped) reporting intervals for RegisterReporter.
func (a *Agent) InventoryInterval() time.Duration {
	return time.Duration(a.Config().InventoryIntervalSeconds) * time.Second
}

// SoftwareInterval is the software.inventory reporting interval.
func (a *Agent) SoftwareInterval() time.Duration {
	return time.Duration(a.Config().SoftwareIntervalSeconds) * time.Second
}

// PostureInterval is the posture reporting interval.
func (a *Agent) PostureInterval() time.Duration {
	return time.Duration(a.Config().PostureIntervalSeconds) * time.Second
}

// PatchScanInterval is the patch.state reporting interval.
func (a *Agent) PatchScanInterval() time.Duration {
	return time.Duration(a.Config().PatchScanIntervalSeconds) * time.Second
}

func (a *Agent) registerBuiltins() {
	a.jobs.Register(protocol.KindScript, script.New())
	a.jobs.Register(protocol.KindInventoryRefresh, jobs.HandlerFunc(a.handleInventoryRefresh))
	a.jobs.Register(protocol.KindAgentConfigure, jobs.HandlerFunc(a.handleAgentConfigure))
	a.jobs.Register(protocol.KindAgentUninstall, jobs.HandlerFunc(a.handleAgentUninstall))
	a.RegisterReporter(ReporterInventory, a.InventoryInterval, func(ctx context.Context) (string, any, error) {
		return protocol.TypeInventory, a.collector.Collect(ctx), nil
	})
}

// tlsConfig builds the TLS policy from the CURRENT trust store and identity.
func (a *Agent) tlsConfig() *tls.Config {
	return transport.NewTLSConfig(a.trust.CAPool(), func() *tls.Certificate {
		if id := a.ident.Load(); id != nil {
			return &id.TLS
		}
		return nil
	})
}

// blobAdapter binds transport.BlobClient to the agent's current server and trust.
type blobAdapter struct{ a *Agent }

func (b blobAdapter) client() *transport.BlobClient {
	return &transport.BlobClient{ServerURL: b.a.Config().ServerURL, TLS: b.a.tlsConfig}
}

// loadTrust opens the trust store, seeding it from the anchors compiled into
// the binary when the installer did not provide files.
func (a *Agent) loadTrust() error {
	defCA, err := buildinfo.CAPEM()
	if err != nil {
		return err
	}
	defKeys, err := buildinfo.CommandKeys()
	if err != nil {
		return err
	}
	store, err := trust.LoadOrSeed(a.paths.CAFile(), a.paths.TrustFile(), defCA, defKeys)
	if err != nil {
		return fmt.Errorf("trust store: %w", err)
	}
	a.trust = store
	return nil
}

// prepare loads state and enrolls if necessary. It returns once the agent
// has an identity and a configuration.
func (a *Agent) prepare(ctx context.Context) error {
	if err := a.paths.Ensure(); err != nil {
		return err
	}
	if err := fsutil.EnsurePrivateDir(a.paths.TempDir()); err != nil {
		return err
	}
	a.removeStaleJobFiles()
	if err := a.loadTrust(); err != nil {
		return err
	}

	cfg, err := config.Load(a.paths)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		cfg = &config.Config{}
		cfg.Normalize()
	default:
		return fmt.Errorf("load config: %w", err)
	}
	boot, bootErr := config.LoadBootstrap(a.paths)
	if bootErr != nil && !errors.Is(bootErr, os.ErrNotExist) {
		return fmt.Errorf("load bootstrap config: %w", bootErr)
	}
	if cfg.ServerURL == "" && boot != nil {
		cfg.ServerURL = boot.ServerURL
	}
	if cfg.ServerURL == "" {
		return errors.New("no server URL configured: run \"dranzo-agent install --server ... --token ...\" first")
	}

	id, err := a.idStore.Load()
	switch {
	case err == nil:
	case errors.Is(err, identity.ErrNoIdentity):
		if boot == nil || boot.Token == "" {
			return errors.New("device is not enrolled and no enrollment token is available")
		}
		id, err = a.enroll(ctx, boot.ServerURL, boot.Token)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("load device identity: %w", err)
	}
	a.ident.Store(id)
	a.deviceID.Store(id.DeviceID)
	a.jobs.SetDeviceID(id.DeviceID)
	a.jobs.SetMaxConcurrent(cfg.MaxConcurrentJobs)
	a.log = a.opts.Logger.With(slog.String("device_id", id.DeviceID))

	cfg.DeviceID = id.DeviceID
	a.cfgMu.Lock()
	a.cfg = *cfg
	a.cfgMu.Unlock()
	if err := config.Save(a.paths, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	// The enrollment token is single-purpose: erase it as soon as an identity exists.
	if err := config.EraseToken(a.paths); err != nil {
		return fmt.Errorf("erase enrollment token: %w", err)
	}
	return nil
}

// removeStaleJobFiles deletes job temp directories a previous run left behind
// (for example after a crash), so script bodies never linger on disk.
func (a *Agent) removeStaleJobFiles() {
	entries, err := os.ReadDir(a.paths.TempDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "dranzo-job-") {
			_ = os.RemoveAll(filepath.Join(a.paths.TempDir(), e.Name()))
		}
	}
}

// enroll retries until the server issues a certificate or ctx ends. The token
// is never logged.
func (a *Agent) enroll(ctx context.Context, serverURL, token string) (*identity.Identity, error) {
	machineID, _ := a.plat.MachineID(ctx)
	params := identity.EnrollParams{
		Token:        token,
		Hostname:     inventory.Hostname(),
		OS:           platform.OSFamily,
		Arch:         inventory.Arch(),
		AgentVersion: a.opts.Version,
		MachineID:    machineID,
	}
	bo := a.opts.Backoff
	if bo == nil {
		bo = transport.NewBackoff()
	}
	for {
		client := transport.NewHTTPClient(a.tlsConfig(), 60*time.Second)
		id, err := identity.Enroll(ctx, client, serverURL, params, a.trust.CAPool())
		if err == nil {
			if err := a.idStore.Save(id); err != nil {
				return nil, fmt.Errorf("store device identity: %w", err)
			}
			a.log.Info("enrolled", slog.String("device_id", id.DeviceID), slog.Time("cert_not_after", id.Leaf.NotAfter))
			return id, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		limit := time.Duration(0)
		if errors.Is(err, identity.ErrTokenRejected) || errors.Is(err, identity.ErrRateLimited) {
			// A rejected token will not start working by hammering the server.
			limit = transport.BackoffRevokedCap
		}
		delay := bo.NextWithCap(limit)
		a.log.Error("enrollment failed", slog.Any("error", err), slog.Duration("retry_in", delay))
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// Enroll performs only the preparation / enrollment step (CLI "enroll").
func (a *Agent) Enroll(ctx context.Context) (deviceID string, err error) {
	if err := a.prepare(ctx); err != nil {
		return "", err
	}
	return a.DeviceID(), nil
}

// Run is the agent main loop. It returns when ctx ends (nil) or on a fatal
// start-up error.
func (a *Agent) Run(ctx context.Context) error {
	if !a.started.CompareAndSwap(false, true) {
		return errors.New("agent already started")
	}
	if err := a.prepare(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	nonces, err := protocol.OpenNonceStore(a.paths.NoncesFile(), nil, 0)
	if err != nil {
		return fmt.Errorf("nonce store: %w", err)
	}
	if nonces.WasReset() {
		a.log.Warn("nonce store was reset; commands issued before now are refused as replays")
	}
	a.verifier = &protocol.Verifier{
		DeviceID: a.DeviceID(),
		Keys:     a.trust,
		Nonces:   nonces,
		Seq:      a.seq,
	}
	cfg := a.Config()
	a.log.Info("agent starting",
		slog.String("version", a.opts.Version),
		slog.String("server", cfg.ServerURL),
		slog.Any("trust_key_ids", a.trust.KeyIDs()))

	a.client = &transport.Client{
		ServerURL: cfg.ServerURL,
		TLS:       a.tlsConfig,
		Logger:    a.log,
		Backoff:   a.opts.Backoff,
		OnState:   a.onConnState,
	}
	a.writeStatus(false, "starting")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.renewLoop(ctx)
	}()

	_ = a.client.Run(ctx, a.serve)

	a.jobs.Shutdown(10 * time.Second)
	wg.Wait()
	a.writeStatus(false, "stopped")
	a.log.Info("agent stopped")
	return nil
}

func (a *Agent) onConnState(connected bool, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	a.writeStatus(connected, msg)
}

func (a *Agent) writeStatus(connected bool, lastErr string) {
	st := &config.Status{
		PID:       os.Getpid(),
		Version:   a.opts.Version,
		Connected: connected,
		Since:     time.Now().UTC(),
		LastError: logging.Redact(truncate(lastErr, 512)),
		UpdatedAt: time.Now().UTC(),
	}
	if id := a.ident.Load(); id != nil {
		st.CertExpiry = id.Leaf.NotAfter.UTC()
	}
	if err := config.SaveStatus(a.paths, st); err != nil {
		a.log.Debug("could not write status file", slog.Any("error", err))
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- outbound messages ----

func (a *Agent) setConn(c *transport.Conn) {
	a.connMu.Lock()
	a.conn = c
	close(a.connChanged)
	a.connChanged = make(chan struct{})
	a.connMu.Unlock()
}

func (a *Agent) currentConn() (*transport.Conn, <-chan struct{}) {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	return a.conn, a.connChanged
}

// Send implements jobs.Sender: it delivers one message on the current
// connection and, while there is none, waits for the next one (or for ctx).
// Blocking gives running jobs back-pressure instead of dropping their output.
func (a *Agent) Send(ctx context.Context, msgType string, payload any) error {
	data, err := protocol.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	for {
		conn, changed := a.currentConn()
		if conn != nil {
			if err := conn.Send(ctx, data); err == nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// sendOn delivers a message on one specific connection only (replies).
func sendOn(ctx context.Context, conn *transport.Conn, msgType string, payload any) error {
	data, err := protocol.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	return conn.Send(ctx, data)
}

// closeAndReconnect ends the current connection on purpose (certificate
// renewed, trust rotated) and reconnects without backoff.
func (a *Agent) closeAndReconnect(reason string) {
	conn, _ := a.currentConn()
	if conn == nil {
		return
	}
	if a.client != nil {
		a.client.ReconnectNow()
	}
	go conn.CloseAfterFlush(websocket.StatusNormalClosure, reason, 2*time.Second)
}

// ---- certificate renewal ----

func (a *Agent) renewLoop(ctx context.Context) {
	first := a.opts.RenewFirstCheck
	if first <= 0 {
		first = 30 * time.Second
	}
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.renewIfNeeded(ctx)
		t.Reset(a.nextRenewCheck())
	}
}

// nextRenewCheck is daily, or more often for short-lived certificates.
func (a *Agent) nextRenewCheck() time.Duration {
	if a.opts.RenewCheckInterval > 0 {
		return a.opts.RenewCheckInterval
	}
	next := 24 * time.Hour
	if id := a.ident.Load(); id != nil {
		if d := id.Leaf.NotAfter.Sub(id.Leaf.NotBefore) / 30; d < next {
			next = d
		}
	}
	if next < time.Minute {
		next = time.Minute
	}
	return next
}

func (a *Agent) renewIfNeeded(ctx context.Context) {
	cur := a.ident.Load()
	if cur == nil || !identity.NeedsRenewal(cur.Leaf, time.Now()) {
		return
	}
	a.log.Info("device certificate is due for renewal", slog.Time("not_after", cur.Leaf.NotAfter))
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := transport.NewHTTPClient(a.tlsConfig(), 90*time.Second)
	next, err := identity.Renew(rctx, client, a.Config().ServerURL, cur, a.trust.CAPool())
	if err != nil {
		a.log.Error("certificate renewal failed", slog.Any("error", err))
		return
	}
	if err := a.idStore.Save(next); err != nil {
		a.log.Error("could not store renewed certificate", slog.Any("error", err))
		return
	}
	a.ident.Store(next)
	a.log.Info("device certificate renewed", slog.Time("not_after", next.Leaf.NotAfter))
	// Reconnect so the server sees (and from then on requires) the new certificate.
	a.closeAndReconnect("certificate renewed")
}
