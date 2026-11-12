// Package update implements signed agent self-update with automatic rollback
// (PROTOCOL.md section 6.4, agent side).
//
// # Trust
//
// An update.available command reaches this package only after the agent core
// verified its Ed25519 signature, target device, validity window and nonce.
// The SHA-256 of the new binary is part of that signed payload, so a file
// whose hash matches is exactly the binary the server signed. Nothing is
// executed, and nothing next to the installed executable is touched, before
// that hash has been verified.
//
// # Sequence
//
//  1. decide: strictly newer semantic version (or force and a different
//     version), not recorded as failed, fields valid, no other update running;
//  2. download to a root-only staging directory (size and hash verified),
//     check the executable format, copy next to the installed executable
//     (hash verified again on the bytes written), run "<new> version";
//  3. write update-state.json, keep the running binary as <exe>.previous,
//     rename the new binary into place, restart;
//  4. the new process counts its start in the state file and waits for
//     hello.ack: confirmed means "installed";
//  5. no hello.ack within ConfirmTimeout, or more than MaxStarts starts
//     without one: <exe>.previous is restored, the version is recorded in
//     failed-updates.json and never installed again, the service restarts and
//     the old version reports "rolled_back".
//
// # Crash safety
//
// Every state write is atomic and fsynced (temp file, fsync, rename, fsync of
// the directory), binaries are fsynced before they are renamed, and the
// directory is fsynced after each rename. The state file is written BEFORE
// the binary is exchanged and never updated to say "exchanged": whether the
// exchange happened is read off the version of the process that finds the
// file. The points at which the process (or the machine) can stop, what is
// on disk then, and what the next start does (V = old version, P = pending):
//
//	UPDATE (running: V)
//	 point                 on disk                                    next start
//	 download:start        nothing                                    V; nothing to do
//	 download:done         staging file in the data directory         V; scratch files removed
//	 stage:copied          <exe>.new (verified)                       V; scratch files removed
//	 state:written         state{swapping P}, exe = V                 V finds pending P != running:
//	                                                                  not installed, reports "failed"
//	                                                                  (interrupted); P may be offered again
//	 swap:previous-kept    + <exe>.previous = V          (Unix)       same as state:written
//	 swap:moved-aside      exe MISSING, <exe>.previous = V (Windows)  the service cannot start: see below
//	 swap:exchanged        exe = P, <exe>.previous = V                P starts: attempt 1, watchdog
//	CONFIRM (running: P)
//	 start:counted         state{swapping, attempt n}                 P: attempt n+1; rollback once
//	                                                                  attempt > MaxStarts
//	 confirm:state-written state{installed}                           P reports "installed" on hello.ack
//	 confirm:reported      state{installed}, server informed          P reports once more, deletes state
//	ROLLBACK (running: P, or the external guard)
//	 rollback:state-written   state{rolling_back}, exe = P            P finds rolling_back: rolls back again
//	 rollback:failed-recorded + P in failed-updates.json              same
//	 rollback:moved-aside     exe MISSING, <exe>.failed = P (Windows) the service cannot start: see below
//	 rollback:restored        exe = V, state{rolling_back}            V finds pending P != running:
//	                                                                  records P as failed (idempotent),
//	                                                                  reports "rolled_back"
//	 rollback:state-final     state{rolled_back}                      V reports "rolled_back" on hello.ack
//	 rollback:reported        state{rolled_back}, server informed     V reports once more, deletes state
//
// On Unix the executable path names a complete, runnable binary at every one
// of these points, because rename(2) replaces it atomically. On Windows a
// running image cannot be replaced, so there are two renames with a window of
// a few microseconds in which the path does not exist; a power loss exactly
// there leaves the service unable to start, with the old binary intact as
// <exe>.previous (and the new or failed one as <exe>.new / <exe>.failed) for
// repair. A failure of the second rename while the process is alive is undone
// immediately.
package update

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Defaults and bounds.
const (
	// DefaultConfirmTimeout is how long a new version has to receive
	// hello.ack before it is rolled back (PROTOCOL.md section 6.4).
	DefaultConfirmTimeout = 5 * time.Minute
	// DefaultMaxStarts is how many starts a new version gets to confirm.
	DefaultMaxStarts = 3
	// MinSizeBytes and MaxSizeBytes bound a plausible agent binary.
	MinSizeBytes = 1 << 20
	MaxSizeBytes = 500 << 20

	defaultIdleWait       = 15 * time.Minute
	defaultInstallTimeout = time.Hour
	defaultRestartGrace   = time.Second
	sendTimeout           = 30 * time.Second
	idlePoll              = 5 * time.Second
)

// buildConfirmTimeout shortens the confirmation watchdog in test builds:
//
//	go build -ldflags "-X github.com/dranzo/dranzormm/agent/internal/update.buildConfirmTimeout=20s"
//
// It can only be set at build time; release builds leave it empty.
var buildConfirmTimeout = ""

// Options configures an Updater.
type Options struct {
	// StateDir is the agent's protected data directory.
	StateDir string
	// ExePath is the installed executable of the running agent.
	ExePath string
	// Version is the version of the running agent.
	Version string
	Log     *slog.Logger
	// Sender delivers update.status messages.
	Sender jobs.Sender
	// Blobs downloads over the pinned mTLS channel, verifying size and SHA-256.
	Blobs jobs.BlobClient
	// Platform runs the version probe of the new binary.
	Platform platform.Platform
	// Restarter replaces the running process after the binary was exchanged.
	Restarter Restarter
	// Busy reports whether jobs are running; the restart waits for idle.
	Busy func() bool

	// ConfirmTimeout and MaxStarts override the defaults (zero: default).
	ConfirmTimeout time.Duration
	MaxStarts      int

	// Seams for tests (zero values select the real implementation).
	now          func() time.Time
	after        func(time.Duration) <-chan time.Time
	probe        func(ctx context.Context, path string) (string, error)
	checkExe     func(path string) error
	failpoint    func(point string)
	renameAside  *bool
	idleWait     time.Duration
	restartGrace *time.Duration
}

// Updater implements agentcore.UpdateHandler.
type Updater struct {
	opts    Options
	log     *slog.Logger
	store   store
	files   fileOps
	version string

	mu       sync.Mutex
	st       *State        // current content of update-state.json (nil: none)
	running  bool          // an update.available is being processed
	watchdog chan struct{} // closed to stop the confirmation watchdog

	helloMu sync.Mutex // serialises hello.ack processing
}

// New prepares an updater. It does not touch the disk; call Start once when
// the agent itself starts.
func New(opts Options) (*Updater, error) {
	switch {
	case opts.StateDir == "":
		return nil, errors.New("update: no state directory")
	case opts.ExePath == "" || !filepath.IsAbs(opts.ExePath):
		return nil, errors.New("update: the executable path must be absolute")
	case opts.Sender == nil || opts.Blobs == nil || opts.Restarter == nil:
		return nil, errors.New("update: sender, blob client and restarter are required")
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.ConfirmTimeout <= 0 {
		opts.ConfirmTimeout = DefaultConfirmTimeout
		if d, err := time.ParseDuration(buildConfirmTimeout); err == nil && d >= time.Second && d <= time.Hour {
			opts.ConfirmTimeout = d
		}
	}
	if opts.MaxStarts <= 0 {
		opts.MaxStarts = DefaultMaxStarts
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.after == nil {
		opts.after = time.After
	}
	if opts.idleWait <= 0 {
		opts.idleWait = defaultIdleWait
	}
	if opts.restartGrace == nil {
		grace := defaultRestartGrace
		opts.restartGrace = &grace
	}
	if opts.checkExe == nil {
		opts.checkExe = func(path string) error {
			return CheckExecutableFile(path, runtime.GOOS, runtime.GOARCH)
		}
	}
	if opts.probe == nil {
		if opts.Platform == nil {
			return nil, errors.New("update: a platform is required to probe the new binary")
		}
		plat := opts.Platform
		opts.probe = func(ctx context.Context, path string) (string, error) {
			return ProbeVersion(ctx, plat, path)
		}
	}
	aside := renameAsideDefault
	if opts.renameAside != nil {
		aside = *opts.renameAside
	}
	return &Updater{
		opts:    opts,
		log:     opts.Log.With(slog.String("component", "update")),
		store:   store{dir: opts.StateDir},
		files:   fileOps{paths: exePaths{exe: opts.ExePath}, renameAside: aside, fp: opts.failpoint},
		version: opts.Version,
	}, nil
}

func (u *Updater) point(name string) {
	if u.opts.failpoint != nil {
		u.opts.failpoint(name)
	}
}

// ---- decision ----

// Action is what the agent does with an update.available command.
type Action int

// Decisions.
const (
	// ActionIgnore: nothing to do (not newer, or the running version).
	ActionIgnore Action = iota
	// ActionRefuse: the offer is invalid or names a version that failed
	// before; "failed" is reported.
	ActionRefuse
	// ActionInstall: download and install.
	ActionInstall
)

// Decision is the outcome of Decide.
type Decision struct {
	Action Action
	Reason string
}

// Validate checks the fields of an update.available payload.
func Validate(upd protocol.UpdateAvailable) error {
	switch {
	case !ValidVersion(upd.Version):
		return errors.New("version is not a semantic version")
	case !protocol.ValidUUID(upd.BlobID):
		return errors.New("blobId is not a valid id")
	case !protocol.ValidSHA256Hex(upd.SHA256) || len(upd.SHA256) != 64:
		return errors.New("sha256 is not a 64-digit hex string")
	case upd.SizeBytes < MinSizeBytes || upd.SizeBytes > MaxSizeBytes:
		return fmt.Errorf("sizeBytes %d is outside %d..%d", upd.SizeBytes, MinSizeBytes, MaxSizeBytes)
	}
	return nil
}

// Decide applies the update policy: install only a valid offer for a version
// that is strictly newer than the running one by semantic-version precedence
// (force also allows an equal or older version, as long as it is not the
// running version itself) and that never failed on this device.
func Decide(running string, upd protocol.UpdateAvailable, failed func(version string) bool) Decision {
	if err := Validate(upd); err != nil {
		return Decision{ActionRefuse, "invalid update: " + err.Error()}
	}
	if SameVersion(upd.Version, running) {
		return Decision{ActionIgnore, "already running this version"}
	}
	// A running version that is not a semantic version (a development build)
	// ranks below every release.
	if cmp, ok := CompareVersions(upd.Version, running); ok && cmp <= 0 && !upd.Force {
		return Decision{ActionIgnore, "not newer than the running version"}
	}
	if failed != nil && failed(upd.Version) {
		return Decision{ActionRefuse, "this version failed on this device before and was rolled back; it is not installed again"}
	}
	return Decision{ActionInstall, ""}
}

// Available implements agentcore.UpdateHandler. It returns at once; the
// update runs in the background.
func (u *Updater) Available(ctx context.Context, upd protocol.UpdateAvailable) {
	d := Decide(u.version, upd, func(v string) bool {
		failed, err := u.store.isFailed(v)
		if err != nil {
			u.log.Warn("could not read the list of failed updates", slog.Any("error", err))
		}
		return failed
	})
	log := u.log.With(slog.String("version", upd.Version))
	switch d.Action {
	case ActionIgnore:
		log.Info("update ignored", slog.String("reason", d.Reason))
		return
	case ActionRefuse:
		log.Warn("update refused", slog.String("reason", d.Reason))
		// ctx is the connection the offer arrived on: the refusal goes back
		// on it or not at all.
		go u.sendWith(ctx, upd.Version, protocol.UpdateFailed, d.Reason)
		return
	}
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		log.Info("update ignored", slog.String("reason", "another update is in progress"))
		return
	}
	u.running = true
	u.mu.Unlock()
	go func() {
		defer func() {
			u.mu.Lock()
			u.running = false
			u.mu.Unlock()
		}()
		u.install(upd)
	}()
}

// ---- install ----

func (u *Updater) install(upd protocol.UpdateAvailable) {
	log := u.log.With(slog.String("version", upd.Version))
	// The command arrived on a connection that completed hello / hello.ack:
	// settle an earlier update first (confirm it, deliver its report).
	u.onHello()
	u.mu.Lock()
	pending := u.st != nil
	u.mu.Unlock()
	if pending {
		log.Info("update ignored", slog.String("reason", "an earlier update is not settled yet"))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultInstallTimeout)
	defer cancel()
	log.Info("update started", slog.Int64("size_bytes", upd.SizeBytes), slog.String("sha256", upd.SHA256))
	restart, err := u.apply(ctx, upd)
	if err != nil {
		log.Error("update failed", slog.Any("error", err))
		u.send(upd.Version, protocol.UpdateFailed, err.Error())
		return
	}
	if restart {
		u.restart("update to " + upd.Version)
	}
}

// apply performs everything up to and including the exchange of the binary.
// It deliberately has no deferred clean-up: at each interruption point the
// files on disk are exactly what a crash would leave behind.
func (u *Updater) apply(ctx context.Context, upd protocol.UpdateAvailable) (restart bool, err error) {
	p := u.files.paths
	staging := u.store.stagingDir()
	staged := filepath.Join(staging, stagedFileName)
	discard := func() {
		_ = os.RemoveAll(staging)
		_ = os.Remove(p.staged())
	}

	u.removeScratch()
	if err := fsutil.EnsurePrivateDir(staging); err != nil {
		return false, err
	}
	u.point("download:start")
	u.send(upd.Version, protocol.UpdateDownloading, "")
	// DownloadFile enforces the signed size and SHA-256 and deletes the file
	// on any mismatch: from here on "staged" is the binary the server signed.
	if err := u.opts.Blobs.DownloadFile(ctx, upd.BlobID, staged, upd.SizeBytes, upd.SHA256); err != nil {
		discard()
		return false, fmt.Errorf("download: %w", err)
	}
	u.point("download:done")
	u.send(upd.Version, protocol.UpdateVerifying, "")
	if err := u.opts.checkExe(staged); err != nil {
		discard()
		return false, fmt.Errorf("the downloaded file was refused: %w", err)
	}
	// Copy instead of move: the file is created inside the program directory
	// (Windows: inherits its ACL; any OS: same volume as the executable, so
	// the exchange is a rename), and its hash is verified on the way.
	if err := copyVerified(staged, p.staged(), upd.SHA256, upd.SizeBytes); err != nil {
		discard()
		return false, fmt.Errorf("stage next to the executable: %w", err)
	}
	if err := matchOwnerAndMode(p.staged(), p.exe); err != nil {
		discard()
		return false, err
	}
	if err := syncFile(p.staged()); err != nil {
		discard()
		return false, err
	}
	_ = os.RemoveAll(staging)
	u.point("stage:copied")

	got, err := u.opts.probe(ctx, p.staged())
	if err != nil {
		discard()
		return false, fmt.Errorf("the new binary does not run: %w", err)
	}
	if !SameVersion(got, upd.Version) {
		discard()
		return false, fmt.Errorf("the new binary reports version %q, expected %q", clip(got), upd.Version)
	}
	if err := u.opts.Restarter.Prepare(); err != nil {
		discard()
		return false, fmt.Errorf("the agent could not be restarted afterwards: %w", err)
	}
	if !u.waitIdle(ctx) {
		discard()
		return false, errors.New("the agent stayed busy with running jobs; the update was postponed")
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	st := &State{
		PendingVersion:  upd.Version,
		PreviousVersion: u.version,
		StartedAt:       u.opts.now().UTC(),
		Phase:           phaseSwapping,
		SHA256:          upd.SHA256,
		ExePath:         p.exe,
	}
	if err := u.store.saveState(st); err != nil {
		discard()
		return false, fmt.Errorf("write update state: %w", err)
	}
	u.st = st
	u.point("state:written")
	if err := u.files.exchange(); err != nil {
		// The executable path still names the running version.
		_ = u.store.deleteState()
		u.st = nil
		discard()
		return false, err
	}
	u.point("swap:exchanged")
	u.log.Info("new binary installed; restarting",
		slog.String("version", upd.Version), slog.String("previous", u.version))
	return true, nil
}

// waitIdle waits until no job is running, so that a restart does not kill a
// package installation or a patch run half-way.
func (u *Updater) waitIdle(ctx context.Context) bool {
	if u.opts.Busy == nil {
		return true
	}
	deadline := u.opts.now().Add(u.opts.idleWait)
	for u.opts.Busy() {
		if !u.opts.now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-u.opts.after(idlePoll):
		}
	}
	return true
}

// restart hands over to the binary now at the executable path. It normally
// does not return.
func (u *Updater) restart(why string) {
	// Let queued update.status frames reach the wire first.
	if g := *u.opts.restartGrace; g > 0 {
		<-u.opts.after(g)
	}
	u.log.Info("restarting the agent", slog.String("reason", why))
	if err := u.opts.Restarter.Restart(); err != nil {
		u.log.Error("restart failed; the binary on disk takes over with the next start of the service",
			slog.Any("error", err))
	}
}

// removeScratch deletes left-overs of an interrupted operation.
func (u *Updater) removeScratch() {
	_ = os.RemoveAll(u.store.stagingDir())
	for _, f := range u.files.paths.scratch() {
		_ = os.Remove(f)
	}
}

// ---- start-up ----

// Start reads update-state.json once, when the agent itself starts ("run"),
// and continues whatever was in flight: it counts this start of a pending
// version and arms the confirmation watchdog, completes an interrupted
// rollback, or keeps an undelivered report for the next hello.ack.
//
// Counting happens synchronously, before the agent connects, so that a
// version that crashes later during start-up is still counted. A rollback
// that is due at start-up is also carried out synchronously, restart
// included: Start then normally does not return, and a version that would
// crash a moment later never gets the chance to win that race.
func (u *Updater) Start() {
	if reason, due := u.resume(); due {
		u.rollback(reason)
	}
}

// resume continues from update-state.json and reports whether a rollback is due.
func (u *Updater) resume() (rollbackReason string, rollbackDue bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	st, err := u.store.loadState()
	if err != nil {
		u.log.Error("discarding unreadable update state", slog.Any("error", err))
		_ = u.store.deleteState()
	}
	if st == nil {
		u.removeScratch()
		return "", false
	}
	u.st = st
	isPending := SameVersion(st.PendingVersion, u.version)
	log := u.log.With(slog.String("pending_version", st.PendingVersion), slog.String("phase", st.Phase))

	switch st.Phase {
	case phaseSwapping:
		if !isPending {
			// Interrupted before the exchange: this is still the old version.
			log.Warn("an update was interrupted before the new binary was installed")
			u.removeScratch()
			st.Phase = phaseFailed
			st.Error = "the update was interrupted before the new version was installed"
			u.saveLocked()
			return "", false
		}
		if st.NoRollback {
			return "", false
		}
		st.Attempt++
		u.saveLocked()
		u.point("start:counted")
		if st.Attempt > u.opts.MaxStarts {
			reason := fmt.Sprintf("version %s was started %d times without confirming a connection to the server",
				st.PendingVersion, st.Attempt-1)
			log.Error("new version keeps restarting; rolling back", slog.Int("attempt", st.Attempt))
			return reason, true
		}
		log.Info("new version started; waiting for the server to confirm the connection",
			slog.Int("attempt", st.Attempt), slog.Duration("timeout", u.opts.ConfirmTimeout))
		stop := make(chan struct{})
		u.watchdog = stop
		expired := u.opts.after(u.opts.ConfirmTimeout)
		go func() {
			select {
			case <-stop:
			case <-expired:
				u.rollback(fmt.Sprintf("version %s did not confirm a connection to the server within %s",
					st.PendingVersion, u.opts.ConfirmTimeout))
			}
		}()

	case phaseRollingBack:
		if isPending {
			log.Warn("a rollback was interrupted; rolling back again")
			return st.Error, true
		}
		// The previous binary is back (this process is it): finish the bookkeeping.
		if err := u.store.recordFailed(st.PendingVersion, st.SHA256, st.Error, u.opts.now()); err != nil {
			log.Error("could not record the failed update", slog.Any("error", err))
		}
		st.Phase = phaseRolledBack
		u.saveLocked()
		u.removeScratch()

	case phaseRolledBack:
		if isPending {
			log.Warn("the rolled-back version is running again; rolling back again")
			return st.Error, true
		}
		u.removeScratch()

	case phaseInstalled:
		if !isPending {
			// The binary was replaced by other means; nothing to report.
			u.clearLocked()
		}

	case phaseFailed:
		// Reported on the next hello.ack.

	default:
		log.Error("discarding update state with an unknown phase")
		u.clearLocked()
	}
	return "", false
}

func (u *Updater) saveLocked() {
	if err := u.store.saveState(u.st); err != nil {
		u.log.Error("could not write update state", slog.Any("error", err))
	}
}

func (u *Updater) clearLocked() {
	if err := u.store.deleteState(); err != nil {
		u.log.Error("could not remove update state", slog.Any("error", err))
	}
	u.st = nil
}

// ---- confirmation and reports ----

// HelloAck is the agent core's hello.ack hook. It returns at once.
func (u *Updater) HelloAck() { go u.onHello() }

// onHello confirms a pending version (the new binary reached the server) and
// delivers a report that is still outstanding.
func (u *Updater) onHello() {
	u.helloMu.Lock()
	defer u.helloMu.Unlock()

	u.mu.Lock()
	st := u.st
	if st == nil {
		u.mu.Unlock()
		return
	}
	isPending := SameVersion(st.PendingVersion, u.version)
	var state string
	confirmed := false
	switch {
	case st.Phase == phaseSwapping && isPending:
		if u.watchdog != nil {
			close(u.watchdog)
			u.watchdog = nil
		}
		st.Phase = phaseInstalled
		st.Error = ""
		u.saveLocked()
		u.log.Info("update confirmed: the new version is connected", slog.String("version", st.PendingVersion))
		confirmed = true
		state = protocol.UpdateInstalled
	case st.Phase == phaseInstalled && isPending:
		state = protocol.UpdateInstalled
	case st.Phase == phaseRolledBack && !isPending:
		state = protocol.UpdateRolledBack
	case st.Phase == phaseFailed:
		state = protocol.UpdateFailed
	default:
		u.mu.Unlock()
		return
	}
	version, errText := st.PendingVersion, st.Error
	u.mu.Unlock()
	if confirmed {
		u.point("confirm:state-written")
	}

	if !u.send(version, state, errText) {
		return // still in the state file: delivered on the next hello.ack
	}
	u.point(reportedPoint(state))
	u.mu.Lock()
	if u.st == st {
		u.clearLocked()
	}
	u.mu.Unlock()
}

func reportedPoint(state string) string {
	if state == protocol.UpdateRolledBack {
		return "rollback:reported"
	}
	return "confirm:reported"
}

// send delivers one update.status; false means it was not handed to a connection.
//
// The update itself is not tied to the connection that delivered the command
// (it outlives a reconnect), so its reports use a context of their own.
func (u *Updater) send(version, state, errText string) bool {
	return u.sendWith(context.Background(), version, state, errText)
}

func (u *Updater) sendWith(parent context.Context, version, state, errText string) bool {
	ctx, cancel := context.WithTimeout(parent, sendTimeout)
	defer cancel()
	err := u.opts.Sender.Send(ctx, protocol.TypeUpdateStatus, protocol.UpdateStatus{
		Version: version, State: state, Error: clip(errText),
	})
	if err != nil {
		u.log.Warn("could not send update.status", slog.String("state", state), slog.Any("error", err))
		return false
	}
	return true
}

// ---- rollback ----

// rollback restores the previous binary and restarts. It is a no-op unless a
// pending version is still unconfirmed.
func (u *Updater) rollback(reason string) {
	previous, done := u.rollbackLocked(reason)
	if done {
		u.restart("rollback to " + previous)
	}
}

func (u *Updater) rollbackLocked(reason string) (previous string, done bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.st
	if st == nil || (st.Phase != phaseSwapping && st.Phase != phaseRollingBack && st.Phase != phaseRolledBack) {
		return "", false
	}
	if u.watchdog != nil {
		close(u.watchdog)
		u.watchdog = nil
	}
	u.log.Error("rolling back the update",
		slog.String("version", st.PendingVersion), slog.String("previous", st.PreviousVersion), slog.String("reason", reason))
	if err := rollbackFiles(u.store, u.files, st, reason, u.opts.checkExe, u.opts.now); err != nil {
		u.log.Error("rollback is not possible; this version keeps running", slog.Any("error", err))
		return "", false
	}
	return st.PreviousVersion, true
}

// rollbackFiles is the durable part of a rollback, shared with Guard:
// mark the state, record the failed version, restore <exe>.previous, mark the
// state again. When there is no usable previous binary the state is marked
// NoRollback and an error is returned; the pending version then stays.
func rollbackFiles(s store, files fileOps, st *State, reason string, checkExe func(string) error, now func() time.Time) error {
	st.Phase = phaseRollingBack
	st.Error = clip(reason)
	if err := s.saveState(st); err != nil {
		return fmt.Errorf("write update state: %w", err)
	}
	files.point("rollback:state-written")

	giveUp := func(err error) error {
		st.Phase = phaseSwapping
		st.NoRollback = true
		_ = s.saveState(st)
		return err
	}
	if err := checkExe(files.paths.previous()); err != nil {
		return giveUp(fmt.Errorf("previous binary %s is not usable: %w", files.paths.previous(), err))
	}
	// Recorded before the binary is restored: whatever happens next, this
	// version is not installed again.
	if err := s.recordFailed(st.PendingVersion, st.SHA256, reason, now()); err != nil {
		return giveUp(fmt.Errorf("record the failed update: %w", err))
	}
	files.point("rollback:failed-recorded")
	if err := files.restore(); err != nil {
		return giveUp(err)
	}
	files.point("rollback:restored")
	// If this last write fails the binary is restored all the same: the next
	// start of the previous version finds "rolling_back" and completes the
	// bookkeeping.
	st.Phase = phaseRolledBack
	_ = s.saveState(st)
	files.point("rollback:state-final")
	return nil
}
