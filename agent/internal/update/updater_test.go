package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ---- fakes ----

// A fake agent binary is a text file "FAKEEXE v=<version>" padded to a
// plausible size. The fake format check wants the prefix and the fake probe
// reads the version, like "<binary> version" would print it.
const fakeMagic = "FAKEEXE v="

func fakeBinary(version string) []byte {
	b := make([]byte, MinSizeBytes+64)
	copy(b, fakeMagic+version+"\n")
	return b
}

func fakeVersionOf(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !bytes.HasPrefix(data, []byte(fakeMagic)) {
		return "", ErrNotExecutable
	}
	line, _, _ := bytes.Cut(data[len(fakeMagic):], []byte("\n"))
	return string(line), nil
}

func fakeCheckExe(path string) error {
	_, err := fakeVersionOf(path)
	return err
}

type fakeSender struct {
	mu     sync.Mutex
	down   bool
	sent   []protocol.UpdateStatus
	notify chan struct{}
}

func (s *fakeSender) Send(_ context.Context, msgType string, payload any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return errors.New("not connected")
	}
	st, ok := payload.(protocol.UpdateStatus)
	if msgType != protocol.TypeUpdateStatus || !ok {
		return fmt.Errorf("unexpected message %s", msgType)
	}
	s.sent = append(s.sent, st)
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return nil
}

func (s *fakeSender) setDown(down bool) {
	s.mu.Lock()
	s.down = down
	s.mu.Unlock()
}

func (s *fakeSender) all() []protocol.UpdateStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.UpdateStatus(nil), s.sent...)
}

func (s *fakeSender) states() string {
	var out []string
	for _, st := range s.all() {
		out = append(out, st.Version+":"+st.State)
	}
	return strings.Join(out, " ")
}

func (s *fakeSender) reset() {
	s.mu.Lock()
	s.sent = nil
	s.mu.Unlock()
}

// fakeBlobs behaves like transport.BlobClient: size and SHA-256 are enforced
// and the file is removed on a mismatch.
type fakeBlobs struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	downloads int
	// lie makes DownloadFile write other bytes than it verified (a staged
	// file that changes between download and installation).
	lie []byte
	// gate, if set, blocks DownloadFile until it is closed.
	gate chan struct{}
}

func (b *fakeBlobs) Download(context.Context, string, io.Writer, int64, string) error {
	return errors.New("not used")
}

func (b *fakeBlobs) Upload(context.Context, string, io.Reader, int64) error {
	return errors.New("not used")
}

func (b *fakeBlobs) DownloadFile(ctx context.Context, blobID, destPath string, sizeBytes int64, sha256Hex string) error {
	b.mu.Lock()
	data, ok := b.blobs[blobID]
	b.downloads++
	gate, lie := b.gate, b.lie
	b.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !ok {
		return errors.New("download blob: HTTP status 404")
	}
	if int64(len(data)) != sizeBytes {
		return errors.New("blob size does not match the signed command")
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != sha256Hex {
		return errors.New("blob SHA-256 does not match the signed command")
	}
	if lie != nil {
		data = lie
	}
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (b *fakeBlobs) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.downloads
}

type fakeRestarter struct {
	mu         sync.Mutex
	prepareErr error
	restartErr error
	restarts   int
	called     chan struct{}
}

func (r *fakeRestarter) Prepare() error { return r.prepareErr }

func (r *fakeRestarter) Restart() error {
	r.mu.Lock()
	r.restarts++
	err := r.restartErr
	r.mu.Unlock()
	select {
	case r.called <- struct{}{}:
	default:
	}
	return err
}

func (r *fakeRestarter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.restarts
}

// waitRestarts waits until Restart was called want times in total.
func (e *env) waitRestarts(want int) {
	e.t.Helper()
	deadline := time.After(10 * time.Second)
	for e.restarter.count() < want {
		select {
		case <-e.restarter.called:
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			e.t.Fatalf("timed out waiting for restart %d (have %d)", want, e.restarter.count())
		}
	}
	if got := e.restarter.count(); got != want {
		e.t.Fatalf("%d restarts, want %d", got, want)
	}
}

// interrupt is the panic value of a simulated crash at an interruption point.
type interrupt struct{ point string }

// env is one simulated device: a program directory with the installed fake
// binary, a state directory, a fake server side and a controllable clock.
type env struct {
	t         *testing.T
	stateDir  string
	exe       string
	sender    *fakeSender
	blobs     *fakeBlobs
	restarter *fakeRestarter
	aside     bool // Windows exchange strategy

	mu        sync.Mutex
	now       time.Time
	timers    []chan time.Time
	crashAt   string
	onPoint   func(point string)
	busy      func() bool
	lastPoint []string
}

func newEnv(t *testing.T, installed string) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		t:         t,
		stateDir:  filepath.Join(root, "state"),
		exe:       filepath.Join(root, "bin", "dranzo-agent"),
		sender:    &fakeSender{notify: make(chan struct{}, 64)},
		blobs:     &fakeBlobs{blobs: map[string][]byte{}},
		restarter: &fakeRestarter{called: make(chan struct{}, 64)},
		now:       time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC),
	}
	for _, d := range []string{e.stateDir, filepath.Dir(e.exe)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(e.exe, fakeBinary(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) paths() exePaths { return exePaths{exe: e.exe} }
func (e *env) store() store    { return store{dir: e.stateDir} }

// offer registers a blob holding a fake binary and returns the command for it.
func (e *env) offer(version string) protocol.UpdateAvailable {
	return e.offerBytes(version, fakeBinary(version))
}

func (e *env) offerBytes(version string, data []byte) protocol.UpdateAvailable {
	id := protocol.NewID()
	e.blobs.mu.Lock()
	e.blobs.blobs[id] = data
	e.blobs.mu.Unlock()
	sum := sha256.Sum256(data)
	return protocol.UpdateAvailable{
		Version: version, BlobID: id, SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(data)), Ring: "test",
	}
}

func (e *env) after(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	e.mu.Lock()
	e.timers = append(e.timers, ch)
	e.mu.Unlock()
	return ch
}

// expire fires the most recently armed timer (the confirmation watchdog).
func (e *env) expire() {
	e.t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.timers) == 0 {
		e.t.Fatal("no timer is armed")
	}
	e.timers[len(e.timers)-1] <- e.now
}

func (e *env) point(name string) {
	e.mu.Lock()
	e.lastPoint = append(e.lastPoint, name)
	crash, hook := e.crashAt == name, e.onPoint
	e.mu.Unlock()
	if hook != nil {
		hook(name)
	}
	if crash {
		panic(interrupt{name})
	}
}

// boot simulates a start of the agent process: the running version is
// whatever binary is installed at the executable path, as on a real device.
func (e *env) boot() *Updater {
	e.t.Helper()
	version, err := fakeVersionOf(e.exe)
	if err != nil {
		e.t.Fatalf("the installed binary cannot start: %v", err)
	}
	u := e.updater(version)
	u.Start()
	return u
}

func (e *env) updater(version string) *Updater {
	e.t.Helper()
	zero := time.Duration(0)
	aside := e.aside
	u, err := New(Options{
		StateDir:  e.stateDir,
		ExePath:   e.exe,
		Version:   version,
		Sender:    e.sender,
		Blobs:     e.blobs,
		Restarter: e.restarter,
		Busy:      e.busy,
		now: func() time.Time {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.now
		},
		after:        e.after,
		probe:        func(_ context.Context, path string) (string, error) { return fakeVersionOf(path) },
		checkExe:     fakeCheckExe,
		failpoint:    e.point,
		renameAside:  &aside,
		restartGrace: &zero,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// crash runs fn and reports the interruption point at which it "crashed".
func (e *env) crash(point string, fn func()) (crashed bool) {
	e.mu.Lock()
	e.crashAt = point
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.crashAt = ""
		e.mu.Unlock()
		if r := recover(); r != nil {
			if _, ok := r.(interrupt); !ok {
				panic(r)
			}
			crashed = true
		}
	}()
	fn()
	return false
}

func (e *env) installed() string {
	e.t.Helper()
	v, err := fakeVersionOf(e.exe)
	if err != nil {
		e.t.Fatalf("installed binary: %v", err)
	}
	return v
}

func (e *env) previous() string {
	v, err := fakeVersionOf(e.paths().previous())
	if err != nil {
		return ""
	}
	return v
}

func (e *env) state() *State {
	e.t.Helper()
	st, err := e.store().loadState()
	if err != nil {
		e.t.Fatalf("state: %v", err)
	}
	return st
}

func (e *env) failedVersions() []string {
	e.t.Helper()
	list, err := e.store().loadFailed()
	if err != nil {
		e.t.Fatalf("failed list: %v", err)
	}
	var out []string
	for _, f := range list {
		out = append(out, f.Version)
	}
	return out
}

func (e *env) wantStates(want string) {
	e.t.Helper()
	if got := e.sender.states(); got != want {
		e.t.Fatalf("update.status messages:\n got  %q\n want %q", got, want)
	}
}

func (e *env) lastStatus() protocol.UpdateStatus {
	e.t.Helper()
	all := e.sender.all()
	if len(all) == 0 {
		e.t.Fatal("no update.status was sent")
	}
	return all[len(all)-1]
}

// noScratch asserts that no temporary file of an operation is left behind.
func (e *env) noScratch() {
	e.t.Helper()
	for _, f := range append(e.paths().scratch(), e.store().stagingDir()) {
		if _, err := os.Lstat(f); err == nil {
			e.t.Errorf("left-over file %s", f)
		}
	}
}

func (e *env) waitStatus(state string) protocol.UpdateStatus {
	e.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		for _, st := range e.sender.all() {
			if st.State == state {
				return st
			}
		}
		select {
		case <-e.sender.notify:
		case <-deadline:
			e.t.Fatalf("timed out waiting for update.status %s (got %q)", state, e.sender.states())
		}
	}
}

// ---- happy path ----

func TestUpdateHappyPath(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.boot()

	// staged -> swapped -> restarted
	u.Available(context.Background(), e.offer("2.0.0"))
	e.waitRestarts(1)
	e.wantStates("2.0.0:downloading 2.0.0:verifying")
	if got := e.installed(); got != "2.0.0" {
		t.Fatalf("installed binary is %s", got)
	}
	if got := e.previous(); got != "1.0.0" {
		t.Fatalf("<exe>.previous is %q", got)
	}
	st := e.state()
	if st == nil || st.Phase != phaseSwapping || st.PendingVersion != "2.0.0" || st.PreviousVersion != "1.0.0" ||
		st.Attempt != 0 || st.ExePath != e.exe || st.StartedAt.IsZero() {
		t.Fatalf("state after the exchange: %+v", st)
	}
	e.noScratch()

	// the new binary starts -> hello.ack -> installed
	e.sender.reset()
	u2 := e.boot()
	if st := e.state(); st.Attempt != 1 || st.Phase != phaseSwapping {
		t.Fatalf("state after the first start: %+v", st)
	}
	e.wantStates("") // nothing is reported before the server confirmed the connection
	u2.onHello()
	e.wantStates("2.0.0:installed")
	if e.state() != nil {
		t.Fatal("state file was not removed after confirmation")
	}
	if got := e.previous(); got != "1.0.0" {
		t.Fatalf("<exe>.previous must be kept for manual recovery, got %q", got)
	}
	if n := e.restarter.count(); n != 1 {
		t.Fatalf("%d restarts", n)
	}
	if len(e.failedVersions()) != 0 {
		t.Fatal("a successful update was recorded as failed")
	}

	// The watchdog is disarmed: an expiry after the confirmation does nothing.
	e.expire()
	u2.onHello()
	time.Sleep(50 * time.Millisecond)
	if e.installed() != "2.0.0" || e.restarter.count() != 1 {
		t.Fatal("the watchdog fired after the update was confirmed")
	}
	e.wantStates("2.0.0:installed")
}

func TestStagedBinaryGetsModeOfInstalledBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	e := newEnv(t, "1.0.0")
	u := e.boot()
	u.Available(context.Background(), e.offer("2.0.0"))
	e.waitRestarts(1)
	for _, f := range []string{e.exe, e.paths().previous()} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o755 {
			t.Errorf("%s has mode %04o, want 0755", f, fi.Mode().Perm())
		}
	}
	fi, err := os.Stat(e.store().statePath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file has mode %04o, want 0600", fi.Mode().Perm())
	}
}

// ---- refusals before anything is exchanged ----

// assertUntouched checks that a refused update changed nothing on the device.
func (e *env) assertUntouched(wantError string) {
	e.t.Helper()
	st := e.waitStatus(protocol.UpdateFailed)
	if !strings.Contains(st.Error, wantError) {
		e.t.Fatalf("failure reason %q does not mention %q", st.Error, wantError)
	}
	if got := e.installed(); got != "1.0.0" {
		e.t.Fatalf("installed binary changed to %s", got)
	}
	if e.previous() != "" {
		e.t.Fatal("<exe>.previous was written")
	}
	if e.state() != nil {
		e.t.Fatal("a state file was written")
	}
	if e.restarter.count() != 0 {
		e.t.Fatal("the agent was restarted")
	}
	if len(e.failedVersions()) != 0 {
		e.t.Fatal("the version was recorded as failed although it was never installed")
	}
	e.noScratch()
}

func TestHashMismatchNeverSwaps(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.boot()
	upd := e.offer("2.0.0")
	upd.SHA256 = strings.Repeat("ab", 32) // the signed hash names another binary
	u.install(upd)
	e.wantStates("2.0.0:downloading 2.0.0:failed")
	e.assertUntouched("SHA-256")
}

func TestSizeMismatchNeverSwaps(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.boot()
	upd := e.offer("2.0.0")
	upd.SizeBytes++
	u.install(upd)
	e.assertUntouched("size")
}

// A staged file that changes after the download was verified is caught by
// the second hash check, on the bytes copied next to the executable.
func TestStagedFileTamperedAfterDownloadNeverSwaps(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.boot()
	upd := e.offer("2.0.0")
	e.blobs.lie = fakeBinary("6.6.6")
	u.install(upd)
	e.wantStates("2.0.0:downloading 2.0.0:verifying 2.0.0:failed")
	e.assertUntouched("signed size and SHA-256")
}

func TestNotAnExecutableNeverSwaps(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.boot()
	u.install(e.offerBytes("2.0.0", bytes.Repeat([]byte("not a program\n"), MinSizeBytes/14+1)))
	e.wantStates("2.0.0:downloading 2.0.0:verifying 2.0.0:failed")
	e.assertUntouched("not an executable")
}

func TestVersionProbeMismatchNeverSwaps(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.boot()
	// The binary is authentic (hash matches) but is not the release the command names.
	u.install(e.offerBytes("2.0.0", fakeBinary("2.0.1")))
	e.wantStates("2.0.0:downloading 2.0.0:verifying 2.0.0:failed")
	e.assertUntouched(`reports version "2.0.1", expected "2.0.0"`)
}

func TestVersionProbeFailureNeverSwaps(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.updater("1.0.0")
	u.opts.probe = func(context.Context, string) (string, error) {
		return "", errors.New("the version command exited with code 1")
	}
	u.Start()
	u.install(e.offer("2.0.0"))
	e.assertUntouched("does not run")
}

func TestNoRestartMechanismNeverSwaps(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.restarter.prepareErr = errors.New("service has no recovery action")
	u := e.boot()
	u.install(e.offer("2.0.0"))
	e.assertUntouched("could not be restarted")
}

func TestBusyAgentPostponesUpdate(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.busy = func() bool {
		// Every poll, a minute passes and the job is still running.
		e.mu.Lock()
		e.now = e.now.Add(time.Minute)
		e.mu.Unlock()
		return true
	}
	u := e.updater("1.0.0")
	u.opts.after = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	u.Start()
	u.install(e.offer("2.0.0"))
	e.assertUntouched("busy")

	// Once the jobs are done the same offer is installed.
	u.opts.Busy = func() bool { return false }
	u.install(e.offer("2.0.0"))
	if e.installed() != "2.0.0" {
		t.Fatal("the update was not installed once the agent was idle")
	}
}

func TestMissingBlobReportsFailed(t *testing.T) {
	e := newEnv(t, "1.0.0")
	u := e.boot()
	upd := e.offer("2.0.0")
	upd.BlobID = protocol.NewID()
	u.install(upd)
	e.assertUntouched("download")
}

func TestOneUpdateAtATime(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.blobs.gate = make(chan struct{})
	u := e.boot()
	u.Available(context.Background(), e.offer("2.0.0"))
	e.waitStatus(protocol.UpdateDownloading)
	// A second offer while the first is downloading is ignored.
	u.Available(context.Background(), e.offer("3.0.0"))
	time.Sleep(50 * time.Millisecond)
	if n := e.blobs.count(); n != 1 {
		t.Fatalf("%d downloads started", n)
	}
	close(e.blobs.gate)
	e.waitRestarts(1)
	if e.installed() != "2.0.0" {
		t.Fatalf("installed %s", e.installed())
	}
	e.wantStates("2.0.0:downloading 2.0.0:verifying")

	// Still unconfirmed: the old process (had the restart failed) takes no other update.
	u.install(e.offer("3.0.0"))
	if e.installed() != "2.0.0" || e.blobs.count() != 1 {
		t.Fatal("a second update was started while the first was not settled")
	}
}

// ---- watchdog and rollback ----

// installTo performs a complete, successful exchange from the installed
// version to version and returns after the (fake) restart.
func (e *env) installTo(version string) {
	e.t.Helper()
	u := e.boot()
	u.install(e.offer(version))
	if got := e.installed(); got != version {
		e.t.Fatalf("installed %s, want %s (statuses %q)", got, version, e.sender.states())
	}
	if e.restarter.count() == 0 {
		e.t.Fatal("no restart after the exchange")
	}
	e.sender.reset()
}

// assertRolledBack checks the device after a completed rollback of 2.0.0.
func (e *env) assertRolledBack(wantReason string) {
	e.t.Helper()
	if got := e.installed(); got != "1.0.0" {
		e.t.Fatalf("installed binary is %s after the rollback", got)
	}
	if got := e.failedVersions(); len(got) != 1 || got[0] != "2.0.0" {
		e.t.Fatalf("failed versions: %v", got)
	}
	// The previous version starts, reconnects and reports.
	e.sender.reset()
	u := e.boot()
	e.wantStates("")
	u.onHello()
	e.wantStates("2.0.0:rolled_back")
	if got := e.lastStatus().Error; !strings.Contains(got, wantReason) {
		e.t.Fatalf("rolled_back error %q does not mention %q", got, wantReason)
	}
	if e.state() != nil {
		e.t.Fatal("state file was not removed after the rollback was reported")
	}
	e.noScratch()

	// The failed version is never retried, not even with force.
	downloads := e.blobs.count()
	e.sender.reset()
	for _, force := range []bool{false, true} {
		upd := e.offer("2.0.0")
		upd.Force = force
		u.Available(context.Background(), upd)
		st := e.waitStatus(protocol.UpdateFailed)
		if !strings.Contains(st.Error, "failed on this device before") {
			e.t.Fatalf("refusal reason: %q", st.Error)
		}
		e.sender.reset()
	}
	if e.blobs.count() != downloads || e.installed() != "1.0.0" || e.state() != nil {
		e.t.Fatal("a failed version was downloaded or installed again")
	}
	// Another version is still welcome.
	u.install(e.offer("2.0.1"))
	if e.installed() != "2.0.1" {
		e.t.Fatal("a newer version was not installed after a rollback")
	}
}

func TestWatchdogTimeoutRollsBack(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")

	e.boot() // 2.0.0 starts, never gets hello.ack
	restarts := e.restarter.count()
	e.expire()
	e.waitRestarts(restarts + 1)
	if st := e.state(); st == nil || st.Phase != phaseRolledBack {
		t.Fatalf("state after the rollback: %+v", st)
	}
	e.assertRolledBack("did not confirm a connection to the server within 5m0s")
}

func TestCrashLoopRollsBack(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")

	// The service manager restarts the new version again and again; it never
	// stays up long enough to confirm (and the watchdog never expires).
	for attempt := 1; attempt <= DefaultMaxStarts; attempt++ {
		e.boot()
		if st := e.state(); st.Attempt != attempt || st.Phase != phaseSwapping {
			t.Fatalf("start %d: state %+v", attempt, st)
		}
		if e.installed() != "2.0.0" {
			t.Fatalf("rolled back too early, at start %d", attempt)
		}
	}
	// One start too many. The rollback is complete when Start returns: a
	// version that crashes right after start-up cannot outrun it.
	restarts := e.restarter.count()
	e.boot()
	if e.installed() != "1.0.0" || e.restarter.count() != restarts+1 {
		t.Fatalf("after the fourth start: installed %s, %d restarts (want 1.0.0 and %d)",
			e.installed(), e.restarter.count(), restarts+1)
	}
	e.assertRolledBack("was started 3 times without confirming")
}

func TestConfirmationOnALaterStartCounts(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	e.boot()
	e.boot()
	u := e.boot() // third start: still allowed
	u.onHello()
	e.wantStates("2.0.0:installed")
	if e.installed() != "2.0.0" || e.state() != nil || len(e.failedVersions()) != 0 {
		t.Fatal("a version that confirmed on its third start was not accepted")
	}
}

func TestRollbackWithoutPreviousBinaryKeepsRunning(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	if err := os.Remove(e.paths().previous()); err != nil {
		t.Fatal(err)
	}
	u := e.boot()
	restarts := e.restarter.count()
	e.expire()
	// The rollback is attempted and given up.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if st := e.state(); st != nil && st.NoRollback {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state: %+v", e.state())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.installed() != "2.0.0" || e.restarter.count() != restarts {
		t.Fatal("the agent restarted although nothing could be restored")
	}
	if len(e.failedVersions()) != 0 {
		t.Fatal("the running version was recorded as failed")
	}
	// No more counting on later starts; a late hello.ack still confirms.
	e.boot()
	if st := e.state(); st.Attempt != 1 {
		t.Fatalf("attempt counted after rollback was given up: %+v", st)
	}
	u.onHello()
	e.wantStates("2.0.0:installed")
	if e.state() != nil {
		t.Fatal("state not cleared")
	}
}

func TestCorruptPreviousBinaryIsNotRestored(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	if err := os.WriteFile(e.paths().previous(), []byte("garbage"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.boot()
	e.expire()
	deadline := time.Now().Add(10 * time.Second)
	for e.state() == nil || !e.state().NoRollback {
		if time.Now().After(deadline) {
			t.Fatalf("state: %+v", e.state())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.installed() != "2.0.0" {
		t.Fatal("a corrupt previous binary was installed")
	}
}

func TestRestartFailureAfterRollbackIsReportedByThePreviousVersion(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	u := e.boot()
	e.restarter.restartErr = errors.New("exec failed")
	restarts := e.restarter.count()
	e.expire()
	e.waitRestarts(restarts + 1)
	// The failed version is still the running process: it must not claim
	// anything on hello.ack.
	u.onHello()
	e.wantStates("")
	e.restarter.restartErr = nil
	e.assertRolledBack("did not confirm")
}

// ---- reports survive a lost connection ----

func TestReportsAreRetriedUntilDelivered(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	u := e.boot()
	e.sender.setDown(true)
	u.onHello() // confirmed, but the report cannot be sent
	if st := e.state(); st == nil || st.Phase != phaseInstalled {
		t.Fatalf("state: %+v", st)
	}
	// Confirmed is confirmed: the watchdog no longer rolls back.
	e.expire()
	time.Sleep(50 * time.Millisecond)
	if e.installed() != "2.0.0" {
		t.Fatal("rolled back after the connection was confirmed")
	}
	// Even across a restart the report is still owed.
	u = e.boot()
	e.sender.setDown(false)
	u.onHello()
	e.wantStates("2.0.0:installed")
	if e.state() != nil {
		t.Fatal("state not cleared")
	}
}

// ---- interruption at every enumerated point ----

func TestInterruptedUpdateRecovers(t *testing.T) {
	cases := []struct {
		point string
		// what the next start finds
		installed string
		pending   bool // a state file exists
	}{
		{"download:start", "1.0.0", false},
		{"download:done", "1.0.0", false},
		{"stage:copied", "1.0.0", false},
		{"state:written", "1.0.0", true},
		{"swap:previous-kept", "1.0.0", true},
		{"swap:exchanged", "2.0.0", true},
	}
	for _, c := range cases {
		t.Run(c.point, func(t *testing.T) {
			e := newEnv(t, "1.0.0")
			u := e.boot()
			if !e.crash(c.point, func() { u.install(e.offer("2.0.0")) }) {
				t.Fatalf("point %s was never reached (points: %v)", c.point, e.lastPoint)
			}
			// Invariant: a complete, runnable binary is installed.
			if got := e.installed(); got != c.installed {
				t.Fatalf("installed %s, want %s", got, c.installed)
			}
			if (e.state() != nil) != c.pending {
				t.Fatalf("state file present: %v", e.state() != nil)
			}
			e.sender.reset()

			u2 := e.boot()
			switch {
			case c.installed == "2.0.0":
				// The exchange was complete: the normal confirmation follows.
				if st := e.state(); st.Attempt != 1 {
					t.Fatalf("state: %+v", st)
				}
				u2.onHello()
				e.wantStates("2.0.0:installed")
				if e.previous() != "1.0.0" {
					t.Fatal("<exe>.previous missing")
				}
			case c.pending:
				// Not installed: the old version says so and may be offered it again.
				u2.onHello()
				e.wantStates("2.0.0:failed")
				if got := e.lastStatus().Error; !strings.Contains(got, "interrupted") {
					t.Fatalf("error %q", got)
				}
			default:
				u2.onHello()
				e.wantStates("")
			}
			if e.state() != nil {
				t.Fatalf("state not settled: %+v", e.state())
			}
			e.noScratch()
			if len(e.failedVersions()) != 0 {
				t.Fatal("an interrupted update was recorded as failed")
			}
			if c.installed == "1.0.0" {
				// The same version can be installed afterwards.
				u2.install(e.offer("2.0.0"))
				if e.installed() != "2.0.0" {
					t.Fatalf("retry did not install (statuses %q)", e.sender.states())
				}
			}
		})
	}
}

func TestInterruptedConfirmationRecovers(t *testing.T) {
	t.Run("start:counted", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		e.installTo("2.0.0")
		if !e.crash("start:counted", func() { e.boot() }) {
			t.Fatal("point not reached")
		}
		if st := e.state(); st.Attempt != 1 {
			t.Fatalf("the start was not counted durably: %+v", st)
		}
		u := e.boot()
		if st := e.state(); st.Attempt != 2 {
			t.Fatalf("state: %+v", st)
		}
		u.onHello()
		e.wantStates("2.0.0:installed")
	})
	t.Run("confirm:state-written", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		e.installTo("2.0.0")
		u := e.boot()
		if !e.crash("confirm:state-written", u.onHello) {
			t.Fatal("point not reached")
		}
		e.wantStates("")
		u = e.boot()
		// Already confirmed: no second watchdog, no further counting.
		if st := e.state(); st.Phase != phaseInstalled || st.Attempt != 1 {
			t.Fatalf("state: %+v", st)
		}
		u.onHello()
		e.wantStates("2.0.0:installed")
		if e.state() != nil {
			t.Fatal("state not cleared")
		}
	})
	t.Run("confirm:reported", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		e.installTo("2.0.0")
		u := e.boot()
		if !e.crash("confirm:reported", u.onHello) {
			t.Fatal("point not reached")
		}
		u = e.boot()
		u.onHello()
		// Reported twice rather than never.
		e.wantStates("2.0.0:installed 2.0.0:installed")
		if e.state() != nil {
			t.Fatal("state not cleared")
		}
	})
}

func TestInterruptedRollbackRecovers(t *testing.T) {
	cases := []struct {
		point     string
		installed string // what the next start finds
	}{
		{"rollback:state-written", "2.0.0"},
		{"rollback:failed-recorded", "2.0.0"},
		{"rollback:restored", "1.0.0"},
		{"rollback:state-final", "1.0.0"},
	}
	for _, c := range cases {
		t.Run(c.point, func(t *testing.T) {
			e := newEnv(t, "1.0.0")
			e.installTo("2.0.0")
			u := e.boot()
			if !e.crash(c.point, func() { u.rollback("the watchdog expired") }) {
				t.Fatalf("point %s was never reached (points: %v)", c.point, e.lastPoint)
			}
			if got := e.installed(); got != c.installed {
				t.Fatalf("installed %s, want %s", got, c.installed)
			}
			if c.installed == "2.0.0" {
				// The failed version starts once more and finishes the rollback itself.
				restarts := e.restarter.count()
				e.boot()
				if e.installed() != "1.0.0" || e.restarter.count() != restarts+1 {
					t.Fatal("the interrupted rollback was not completed synchronously at start-up")
				}
			}
			e.assertRolledBack("the watchdog expired")
		})
	}
	t.Run("rollback:reported", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		e.installTo("2.0.0")
		e.boot().rollback("the watchdog expired")
		u := e.boot()
		if !e.crash("rollback:reported", u.onHello) {
			t.Fatal("point not reached")
		}
		e.assertRolledBack("the watchdog expired")
	})
}

// ---- the Windows exchange strategy (rename aside), run on any OS ----

func TestRenameAsideStrategy(t *testing.T) {
	t.Run("update and rollback", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		e.aside = true
		e.installTo("2.0.0")
		if e.previous() != "1.0.0" {
			t.Fatal("<exe>.previous missing")
		}
		e.boot()
		restarts := e.restarter.count()
		e.expire()
		e.waitRestarts(restarts + 1)
		if e.installed() != "1.0.0" {
			t.Fatalf("installed %s", e.installed())
		}
		// The failed binary was moved aside (it would still be running on Windows).
		if v, _ := fakeVersionOf(e.paths().failedAside()); v != "2.0.0" {
			t.Fatalf("<exe>.failed holds %q", v)
		}
		e.assertRolledBack("did not confirm")
	})
	t.Run("second rename fails: old binary is put back", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		e.aside = true
		e.onPoint = func(point string) {
			if point == "swap:moved-aside" {
				// Whatever makes the second rename fail (here: the source vanished).
				_ = os.Remove(e.paths().staged())
			}
		}
		u := e.boot()
		u.install(e.offer("2.0.0"))
		if e.installed() != "1.0.0" {
			t.Fatal("the old binary was not restored")
		}
		if e.state() != nil || e.restarter.count() != 0 {
			t.Fatal("state left behind or restart issued")
		}
		if st := e.waitStatus(protocol.UpdateFailed); !strings.Contains(st.Error, "install the new executable") {
			t.Fatalf("error %q", st.Error)
		}
	})
	t.Run("power loss between the two renames", func(t *testing.T) {
		// The documented Windows hazard: the path is empty, both binaries
		// are still on disk for repair.
		e := newEnv(t, "1.0.0")
		e.aside = true
		u := e.boot()
		if !e.crash("swap:moved-aside", func() { u.install(e.offer("2.0.0")) }) {
			t.Fatal("point not reached")
		}
		if _, err := os.Stat(e.exe); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("executable path: %v", err)
		}
		if e.previous() != "1.0.0" {
			t.Fatal("old binary lost")
		}
		if v, _ := fakeVersionOf(e.paths().staged()); v != "2.0.0" {
			t.Fatal("new binary lost")
		}
	})
}

// ---- start-up with odd state files ----

func TestStartDiscardsUnusableState(t *testing.T) {
	write := func(e *env, content string) {
		if err := os.WriteFile(e.store().statePath(), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("corrupt", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		write(e, "{not json")
		u := e.boot()
		u.onHello()
		if e.state() != nil || e.installed() != "1.0.0" || e.restarter.count() != 0 {
			t.Fatal("corrupt state had an effect")
		}
		e.wantStates("")
	})
	t.Run("unknown phase", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		write(e, `{"pendingVersion":"2.0.0","previousVersion":"1.0.0","phase":"teleporting"}`)
		e.boot().onHello()
		if e.state() != nil || e.restarter.count() != 0 {
			t.Fatal("unknown phase had an effect")
		}
	})
	t.Run("installed report of another version", func(t *testing.T) {
		e := newEnv(t, "1.0.0")
		write(e, `{"pendingVersion":"2.0.0","previousVersion":"1.0.0","phase":"installed"}`)
		e.boot().onHello()
		e.wantStates("")
		if e.state() != nil {
			t.Fatal("state not cleared")
		}
	})
	t.Run("group-readable state file is not trusted", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Unix permissions")
		}
		e := newEnv(t, "2.0.0")
		write(e, `{"pendingVersion":"2.0.0","previousVersion":"1.0.0","phase":"rolling_back"}`)
		if err := os.Chmod(e.store().statePath(), 0o644); err != nil {
			t.Fatal(err)
		}
		e.boot()
		time.Sleep(50 * time.Millisecond)
		if e.restarter.count() != 0 || e.installed() != "2.0.0" {
			t.Fatal("a state file writable or readable by others triggered a rollback")
		}
	})
}

func TestStartRemovesLeftOvers(t *testing.T) {
	e := newEnv(t, "1.0.0")
	p := e.paths()
	if err := os.MkdirAll(e.store().stagingDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range append(p.scratch(), filepath.Join(e.store().stagingDir(), stagedFileName)) {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p.previous(), fakeBinary("0.9.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.boot()
	e.noScratch()
	if e.previous() != "0.9.0" {
		t.Fatal("<exe>.previous must survive the clean-up")
	}
}

func TestNewValidatesOptions(t *testing.T) {
	e := newEnv(t, "1.0.0")
	base := Options{StateDir: e.stateDir, ExePath: e.exe, Sender: e.sender, Blobs: e.blobs, Restarter: e.restarter}
	if _, err := New(base); err == nil {
		t.Error("a missing platform (no way to probe the new binary) was accepted")
	}
	for name, mutate := range map[string]func(*Options){
		"no state dir":  func(o *Options) { o.StateDir = "" },
		"relative exe":  func(o *Options) { o.ExePath = "dranzo-agent" },
		"no sender":     func(o *Options) { o.Sender = nil },
		"no blobs":      func(o *Options) { o.Blobs = nil },
		"no restarter":  func(o *Options) { o.Restarter = nil },
		"empty exe":     func(o *Options) { o.ExePath = "" },
		"probe missing": func(o *Options) { o.probe = nil },
	} {
		o := base
		o.probe = func(context.Context, string) (string, error) { return "", nil }
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConfirmTimeoutDefaultAndBuildOverride(t *testing.T) {
	e := newEnv(t, "1.0.0")
	if got := e.updater("1.0.0").opts.ConfirmTimeout; got != 5*time.Minute {
		t.Fatalf("default confirm timeout %s", got)
	}
	defer func(old string) { buildConfirmTimeout = old }(buildConfirmTimeout)
	buildConfirmTimeout = "20s"
	if got := e.updater("1.0.0").opts.ConfirmTimeout; got != 20*time.Second {
		t.Fatalf("build override: %s", got)
	}
	for _, bad := range []string{"0s", "1ms", "48h", "soon"} {
		buildConfirmTimeout = bad
		if got := e.updater("1.0.0").opts.ConfirmTimeout; got != 5*time.Minute {
			t.Fatalf("override %q was accepted: %s", bad, got)
		}
	}
}
