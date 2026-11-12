package update_test

// End-to-end tests of self-update with REAL agent binaries against the
// in-process fake gateway (internal/testserver):
//
//   - TestE2EForeground runs "dranzo-agent run --foreground" as a child
//     process: v1 enrolls, is updated to v2 (re-exec in place), reports
//     "installed"; a v3 that cannot reach the server is rolled back to v2,
//     which reports "rolled_back" and refuses a second offer of v3.
//   - TestE2ESystemd (opt-in, see e2e_systemd_test.go) does the same through
//     "dranzo-agent install" under a real systemd.
//
// The agent binaries are built by the test with "go build" (version stamped
// with -ldflags, confirmation watchdog shortened at build time). The broken
// releases are the real agent with one defect injected through "go build
// -overlay"; no source file of the repository is modified.
//
// Environment:
//
//	DRANZO_UPDATE_E2E=0             skip these tests
//	DRANZO_UPDATE_E2E=1             run them even with -short / on Windows
//	DRANZO_UPDATE_E2E_BIN=<dir>     use binaries built earlier instead of building
//	DRANZO_UPDATE_E2E_BUILD=<dir>   only build the binaries into <dir>, for
//	DRANZO_UPDATE_E2E_TARGET=os/arch  (default: this platform), then stop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
	"github.com/dranzo/dranzormm/agent/internal/trust"
	"github.com/dranzo/dranzormm/agent/internal/update"
)

const (
	modulePath = "github.com/dranzo/dranzormm/agent"
	// e2eConfirm is the confirmation watchdog compiled into the test builds.
	e2eConfirm = 12 * time.Second
	e2eWait    = 90 * time.Second
)

// Versions used by the scenarios and the build variant of each.
const (
	verOld       = "1.0.0"
	verNew       = "2.0.0"
	verNoConnect = "3.0.0" // real agent whose TLS trusts no CA: never connects
	verCrash     = "3.1.0" // real agent that fails during start-up (exit 1)
	verGuard     = "2.1.0" // real agent plus the recommended "update-guard" command
	verTiny      = "3.2.0" // prints the right version, otherwise exits at once
)

func exeSuffix(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

func binName(version, goos string) string { return "agent-" + version + exeSuffix(goos) }

// moduleRoot is the agent module directory (this package is internal/update).
func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("module root not found: %v", err)
	}
	return root
}

// Sources injected with -overlay to make the broken / extended variants.
const (
	crashSource = `package main

import (
	"errors"

	"` + modulePath + `/internal/agentcore"
)

// A release with a defect in its start-up path: every start fails.
func init() {
	features = append(features, func(*agentcore.Agent) error {
		return errors.New("simulated defect: this release cannot start")
	})
}
`
	// The integration recommended in the hand-over report, expressed as an
	// overlay because main.go is not part of the update package's scope.
	guardSource = `package main

import (
	"fmt"
	"os"

	"` + modulePath + `/internal/config"
	"` + modulePath + `/internal/update"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "update-guard" {
		rolledBack, err := update.Guard(update.GuardOptions{StateDir: config.ResolvePaths("").StateDir})
		fmt.Fprintf(os.Stderr, "update-guard: rolled back: %v, error: %v\n", rolledBack, err)
		os.Exit(0)
	}
}
`
	tinySource = `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("dranzo-agent ` + verTiny + ` (%s)")
		return
	}
	os.Exit(3)
}
`
)

type builder struct {
	t      *testing.T
	root   string
	outDir string
	goos   string
	goarch string
	work   string
}

func (b *builder) run(dir string, args ...string) {
	b.t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS="+b.goos, "GOARCH="+b.goarch, "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		b.t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// agent builds the real agent stamped with version; overlay maps a source
// path (relative to the module root) to replacement content.
func (b *builder) agent(version string, overlay map[string]string) {
	b.t.Helper()
	args := []string{"build", "-trimpath", "-ldflags",
		"-X " + modulePath + "/internal/buildinfo.Version=" + version +
			" -X " + modulePath + "/internal/update.buildConfirmTimeout=" + e2eConfirm.String()}
	if len(overlay) > 0 {
		replace := map[string]string{}
		for rel, content := range overlay {
			tmp := filepath.Join(b.work, version+"-"+filepath.Base(rel))
			if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
				b.t.Fatal(err)
			}
			replace[filepath.Join(b.root, filepath.FromSlash(rel))] = tmp
		}
		data, err := json.Marshal(map[string]any{"Replace": replace})
		if err != nil {
			b.t.Fatal(err)
		}
		file := filepath.Join(b.work, version+"-overlay.json")
		if err := os.WriteFile(file, data, 0o600); err != nil {
			b.t.Fatal(err)
		}
		args = append(args, "-overlay", file)
	}
	args = append(args, "-o", filepath.Join(b.outDir, binName(version, b.goos)), "./cmd/dranzo-agent")
	b.run(b.root, args...)
}

// noTrustOverlay is internal/transport/tls.go with the pinned CA pool
// replaced by an empty one: a release shipped with the wrong CA.
func (b *builder) noTrustOverlay() map[string]string {
	b.t.Helper()
	const rel = "internal/transport/tls.go"
	src, err := os.ReadFile(filepath.Join(b.root, filepath.FromSlash(rel)))
	if err != nil {
		b.t.Fatal(err)
	}
	const from, to = "RootCAs:    roots,", "RootCAs:    x509.NewCertPool(),"
	if bytes.Count(src, []byte(from)) != 1 {
		b.t.Fatalf("%s changed: cannot inject the wrong-CA defect (expected exactly one %q)", rel, from)
	}
	return map[string]string{rel: strings.Replace(string(src), from, to, 1)}
}

func (b *builder) tiny() {
	b.t.Helper()
	dir := filepath.Join(b.work, "tiny")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.t.Fatal(err)
	}
	family := map[string]string{"darwin": "macos"}[b.goos]
	if family == "" {
		family = b.goos
	}
	files := map[string]string{
		"go.mod":  "module tiny\n\ngo 1.24\n",
		"main.go": fmt.Sprintf(tinySource, family),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			b.t.Fatal(err)
		}
	}
	b.run(dir, "build", "-trimpath", "-o", filepath.Join(b.outDir, binName(verTiny, b.goos)), ".")
}

func (b *builder) all() {
	b.t.Helper()
	b.agent(verOld, nil)
	b.agent(verNew, nil)
	b.agent(verNoConnect, b.noTrustOverlay())
	b.agent(verCrash, map[string]string{"cmd/dranzo-agent/wire_zz_e2e_crash.go": crashSource})
	b.agent(verGuard, map[string]string{"cmd/dranzo-agent/wire_zz_e2e_guard.go": guardSource})
	b.tiny()
}

var (
	binOnce sync.Once
	binDir  string
	binErr  string
)

// e2eBinaries returns the directory with the agent builds, or skips.
func e2eBinaries(t *testing.T) string {
	t.Helper()
	mode := os.Getenv("DRANZO_UPDATE_E2E")
	if mode == "0" {
		t.Skip("DRANZO_UPDATE_E2E=0")
	}
	if dir := os.Getenv("DRANZO_UPDATE_E2E_BIN"); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, binName(verOld, runtime.GOOS))); err != nil {
			t.Fatalf("DRANZO_UPDATE_E2E_BIN: %v", err)
		}
		return dir
	}
	if mode != "1" {
		if testing.Short() {
			t.Skip("builds agent binaries; skipped with -short")
		}
		if runtime.GOOS == "windows" {
			t.Skip("opt-in on Windows: set DRANZO_UPDATE_E2E=1")
		}
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is needed to build the agent binaries")
	}
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "dranzo-update-e2e-")
		if err != nil {
			binErr = err.Error()
			return
		}
		binDir = dir
		b := &builder{t: t, root: moduleRoot(t), outDir: dir, goos: runtime.GOOS, goarch: runtime.GOARCH, work: t.TempDir()}
		b.all()
	})
	if binErr != "" || binDir == "" {
		t.Fatalf("building the agent binaries failed earlier %s", binErr)
	}
	return binDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// TestE2EBuildBinaries only builds the binaries for another platform (used to
// run the end-to-end tests inside a container without a Go toolchain).
func TestE2EBuildBinaries(t *testing.T) {
	out := os.Getenv("DRANZO_UPDATE_E2E_BUILD")
	if out == "" {
		t.Skip("set DRANZO_UPDATE_E2E_BUILD=<dir> to build the end-to-end binaries")
	}
	goos, goarch := runtime.GOOS, runtime.GOARCH
	if target := os.Getenv("DRANZO_UPDATE_E2E_TARGET"); target != "" {
		var ok bool
		if goos, goarch, ok = strings.Cut(target, "/"); !ok {
			t.Fatalf("DRANZO_UPDATE_E2E_TARGET=%q is not os/arch", target)
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	b := &builder{t: t, root: moduleRoot(t), outDir: out, goos: goos, goarch: goarch, work: t.TempDir()}
	b.all()
}

// ---- shared scenario helpers ----

type e2e struct {
	began  time.Time
	t      *testing.T
	srv    *testserver.Server
	bins   string
	device string
	exe    string // the installed agent binary
	data   config.Paths
}

func (e *e2e) binary(version string) []byte {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(e.bins, binName(version, runtime.GOOS)))
	if err != nil {
		e.t.Fatal(err)
	}
	return data
}

// offer sends a signed update.available for the given binary and returns the
// message index from which to look for the agent's answers.
func (e *e2e) offer(version string, binary []byte, tamper func(*protocol.UpdateAvailable)) int {
	e.t.Helper()
	blobID, sum := e.srv.AddBlob(binary)
	upd := protocol.UpdateAvailable{
		SignedCommon: testserver.Common(e.device),
		Version:      version, BlobID: blobID, SHA256: sum, SizeBytes: int64(len(binary)), Ring: "e2e",
	}
	if tamper != nil {
		tamper(&upd)
	}
	if err := e.srv.AwaitConnected(e.device, e2eWait); err != nil {
		e.t.Fatalf("agent is not connected: %v", err)
	}
	mark := e.srv.Mark(e.device)
	if _, err := e.srv.SendSigned(e.device, protocol.TypeUpdateAvailable, upd); err != nil {
		e.t.Fatalf("send update.available: %v", err)
	}
	e.t.Logf("%6.1fs -> update.available %s (%d bytes)", time.Since(e.began).Seconds(), version, len(binary))
	return mark
}

// status waits for update.status with the given state for version.
func (e *e2e) status(from int, version, state string) protocol.UpdateStatus {
	e.t.Helper()
	var got protocol.UpdateStatus
	_, err := e.srv.Await(e.device, from, e2eWait, func(env *protocol.Envelope) bool {
		if env.Type != protocol.TypeUpdateStatus {
			return false
		}
		var st protocol.UpdateStatus
		if json.Unmarshal(env.Payload, &st) != nil {
			return false
		}
		if st.Version == version && st.State == state {
			got = st
			return true
		}
		return false
	})
	if err != nil {
		e.t.Fatalf("no update.status %s for %s: %v (received: %s)", state, version, err, e.statuses(from))
	}
	e.t.Logf("%6.1fs <- update.status %s %s %s", time.Since(e.began).Seconds(), got.Version, got.State, got.Error)
	return got
}

func (e *e2e) statuses(from int) string {
	var out []string
	for _, env := range e.srv.Messages(e.device, from) {
		if env.Type == protocol.TypeUpdateStatus {
			out = append(out, string(env.Payload))
		}
	}
	return strings.Join(out, " ")
}

// noStatus asserts that no update.status with that state arrived since from.
func (e *e2e) noStatus(from int, state string) {
	e.t.Helper()
	for _, env := range e.srv.Messages(e.device, from) {
		var st protocol.UpdateStatus
		if env.Type == protocol.TypeUpdateStatus && json.Unmarshal(env.Payload, &st) == nil && st.State == state {
			e.t.Fatalf("unexpected update.status %s: %s", state, env.Payload)
		}
	}
}

// helloVersion waits until the connected agent announced version in hello.
func (e *e2e) helloVersion(version string) {
	e.t.Helper()
	deadline := time.Now().Add(e2eWait)
	for {
		h := e.srv.Hello(e.device)
		if h != nil && h.AgentVersion == version && e.srv.AwaitConnected(e.device, time.Millisecond) == nil {
			return
		}
		if time.Now().After(deadline) {
			got := "none"
			if h != nil {
				got = h.AgentVersion
			}
			e.t.Fatalf("the connected agent is %s, want %s", got, version)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// versionOf runs "<path> version".
func (e *e2e) versionOf(path string) string {
	e.t.Helper()
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		e.t.Fatalf("%s version: %v", path, err)
	}
	v, err := update.ParseVersionOutput(string(out))
	if err != nil {
		e.t.Fatalf("%s version: %q: %v", path, out, err)
	}
	return v
}

func (e *e2e) wantInstalled(version, previous string) {
	e.t.Helper()
	if got := e.versionOf(e.exe); got != version {
		e.t.Fatalf("installed binary is %s, want %s", got, version)
	}
	if previous != "" {
		if got := e.versionOf(e.exe + ".previous"); got != previous {
			e.t.Fatalf("<exe>.previous is %s, want %s", got, previous)
		}
	}
}

func (e *e2e) stateFile() string { return filepath.Join(e.data.StateDir, "update-state.json") }

func (e *e2e) wantNoState() {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := os.Stat(e.stateFile())
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(e.stateFile())
			e.t.Fatalf("update-state.json still exists: %s", data)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (e *e2e) failedList() string {
	data, _ := os.ReadFile(filepath.Join(e.data.StateDir, "failed-updates.json"))
	return string(data)
}

// updateAndRollback is the scenario shared by the foreground and the systemd
// test, starting from a connected agent of version verOld.
func (e *e2e) updateAndRollback() {
	t := e.t
	e.helloVersion(verOld)

	// A blob that does not match the signed hash is never installed.
	from := e.offer(verNew, e.binary(verNew), func(u *protocol.UpdateAvailable) {
		u.SHA256 = strings.Repeat("ab", 32)
	})
	if st := e.status(from, verNew, protocol.UpdateFailed); !strings.Contains(st.Error, "SHA-256") {
		t.Fatalf("failure reason: %q", st.Error)
	}
	e.wantInstalled(verOld, "")
	e.wantNoState()

	// v1 -> v2: the running agent becomes v2, reconnects, reports "installed".
	from = e.offer(verNew, e.binary(verNew), nil)
	e.status(from, verNew, protocol.UpdateDownloading)
	e.status(from, verNew, protocol.UpdateVerifying)
	e.status(from, verNew, protocol.UpdateInstalled)
	e.helloVersion(verNew)
	e.wantInstalled(verNew, verOld)
	e.wantNoState()
	e.noStatus(from, protocol.UpdateRolledBack)

	// An offer of the running or an older version is ignored without a download.
	blobs := e.srv.Hits("blob")
	from = e.offer(verOld, e.binary(verOld), nil)
	e.offer(verNew, e.binary(verNew), nil)
	time.Sleep(2 * time.Second)
	if e.srv.Hits("blob") != blobs || e.statuses(from) != "" {
		t.Fatalf("an offer that is not newer had an effect: %s", e.statuses(from))
	}

	// v2 -> broken v3 (cannot connect): rolled back to v2, which reports it.
	from = e.offer(verNoConnect, e.binary(verNoConnect), nil)
	e.status(from, verNoConnect, protocol.UpdateVerifying)
	st := e.status(from, verNoConnect, protocol.UpdateRolledBack)
	if !strings.Contains(st.Error, "did not confirm a connection") {
		t.Fatalf("rollback reason: %q", st.Error)
	}
	e.helloVersion(verNew)
	e.wantInstalled(verNew, verNew)
	e.wantNoState()
	e.noStatus(from, protocol.UpdateInstalled)
	if !strings.Contains(e.failedList(), `"`+verNoConnect+`"`) {
		t.Fatalf("failed-updates.json does not list %s: %s", verNoConnect, e.failedList())
	}

	// A second offer of v3 is refused without a download.
	blobs = e.srv.Hits("blob")
	from = e.offer(verNoConnect, e.binary(verNoConnect), nil)
	if st := e.status(from, verNoConnect, protocol.UpdateFailed); !strings.Contains(st.Error, "failed on this device before") {
		t.Fatalf("refusal reason: %q", st.Error)
	}
	if e.srv.Hits("blob") != blobs {
		t.Fatal("the failed version was downloaded again")
	}
	e.wantInstalled(verNew, "")
	e.helloVersion(verNew)
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// ---- foreground mode ----

// supervised runs the agent in the foreground. Like any supervisor of a
// foreground agent it starts the agent again when it exits with
// update.ExitCodeRestart (Windows; on Unix the agent re-executes in place).
type supervised struct {
	t    *testing.T
	exe  string
	args []string
	log  *os.File

	mu    sync.Mutex
	cmd   *exec.Cmd
	pids  []int
	stop  bool
	ended chan struct{}
}

func (s *supervised) start() {
	s.ended = make(chan struct{})
	go func() {
		defer close(s.ended)
		for {
			cmd := exec.Command(s.exe, s.args...)
			cmd.Stdout, cmd.Stderr = s.log, s.log
			s.mu.Lock()
			if s.stop {
				s.mu.Unlock()
				return
			}
			if err := cmd.Start(); err != nil {
				s.mu.Unlock()
				s.t.Errorf("start agent: %v", err)
				return
			}
			s.cmd = cmd
			s.pids = append(s.pids, cmd.Process.Pid)
			s.mu.Unlock()
			_ = cmd.Wait()
			if cmd.ProcessState.ExitCode() != update.ExitCodeRestart {
				return
			}
		}
	}()
}

func (s *supervised) starts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pids)
}

func (s *supervised) alive() bool {
	select {
	case <-s.ended:
		return false
	default:
		return true
	}
}

func (s *supervised) shutdown() {
	s.mu.Lock()
	s.stop = true
	cmd := s.cmd
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}
	select {
	case <-s.ended:
	case <-time.After(15 * time.Second):
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-s.ended
	}
}

func TestE2EForeground(t *testing.T) {
	bins := e2eBinaries(t)
	srv, err := testserver.New(testserver.Options{HeartbeatSeconds: 15})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	root := t.TempDir()
	paths := config.ResolvePaths(filepath.Join(root, "data"))
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := trust.Install(paths.CAFile(), paths.TrustFile(), srv.CAPEM, srv.TrustKeys()); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveBootstrap(paths, &config.Bootstrap{ServerURL: srv.URL, Token: srv.Token}); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(root, "program", "dranzo-agent"+exeSuffix(runtime.GOOS))
	copyExecutable(t, filepath.Join(bins, binName(verOld, runtime.GOOS)), exe)
	// The test's temp directory may be reached through a symbolic link
	// (macOS: /var -> /private/var); the agent works on the resolved path.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	logFile, err := os.Create(filepath.Join(root, "agent-output.log"))
	if err != nil {
		t.Fatal(err)
	}
	sup := &supervised{t: t, exe: exe, args: []string{"run", "--foreground", "--data-dir", paths.StateDir}, log: logFile}
	sup.start()
	defer func() {
		sup.shutdown()
		_ = logFile.Close()
		if t.Failed() {
			out, _ := os.ReadFile(logFile.Name())
			if len(out) > 16<<10 {
				out = out[len(out)-16<<10:]
			}
			t.Logf("agent output (tail):\n%s", out)
		}
	}()

	device, err := srv.AwaitDevice(e2eWait)
	if err != nil {
		t.Fatalf("the agent did not enroll: %v", err)
	}
	e := &e2e{began: time.Now(), t: t, srv: srv, bins: bins, device: device, exe: exe, data: paths}
	e.updateAndRollback()

	if !sup.alive() {
		t.Fatal("the agent process ended")
	}
	if runtime.GOOS != "windows" {
		// Re-exec in place: one process for v1, v2, v3 and v2 again.
		if n := sup.starts(); n != 1 {
			t.Fatalf("the agent was started %d times; it should have re-executed in place", n)
		}
		st, err := config.LoadStatus(paths)
		if err != nil || st.PID != sup.pids[0] || st.Version != verNew {
			t.Fatalf("status file: %+v, %v (supervised pid %d)", st, err, sup.pids[0])
		}
	}
	// Permissions of what the update left behind.
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{
			exe:               0o755,
			exe + ".previous": 0o755,
			filepath.Join(paths.StateDir, "failed-updates.json"): 0o600,
		} {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != want {
				t.Errorf("%s has mode %04o, want %04o", path, fi.Mode().Perm(), want)
			}
		}
		for _, leftover := range []string{exe + ".new", exe + ".rollback.tmp", exe + ".previous.tmp", filepath.Join(paths.StateDir, "update-staging")} {
			if _, err := os.Lstat(leftover); err == nil {
				t.Errorf("left-over %s", leftover)
			}
		}
	}
}
