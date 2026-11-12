//go:build windows

package script

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Live Windows tests (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit): real PowerShell and cmd.exe scripts through the
// real job manager and the real Windows platform (job objects, CreateProcess).
// The scripts only print, start ping.exe against 127.0.0.1 and exit.

func requireLiveWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
}

func runningAsSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// processAlive reports whether pid is a running process.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// ERROR_INVALID_PARAMETER: no such process. Access denied: it exists.
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func waitGone(t *testing.T, what string, pid int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still running", what, pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// liveRecorder is the jobs.Sender of these tests.
type liveRecorder struct {
	mu  sync.Mutex
	out map[string]*strings.Builder
	res map[string]protocol.JobResult
}

func (r *liveRecorder) Send(_ context.Context, _ string, payload any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch p := payload.(type) {
	case protocol.JobOutput:
		key := p.JobRunID + "/" + p.Stream
		if r.out[key] == nil {
			r.out[key] = &strings.Builder{}
		}
		r.out[key].WriteString(p.Data)
	case protocol.JobResult:
		r.res[p.JobRunID] = p
	}
	return nil
}

func (r *liveRecorder) stream(id, stream string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b := r.out[id+"/"+stream]; b != nil {
		return b.String()
	}
	return ""
}

func (r *liveRecorder) wait(t *testing.T, id string, timeout time.Duration) protocol.JobResult {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		res, ok := r.res[id]
		r.mu.Unlock()
		if ok {
			return res
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no result for %s within %v", id, timeout)
	return protocol.JobResult{}
}

// awaitStdout waits until the job's stdout matches re and returns the first submatch.
func (r *liveRecorder) awaitStdout(t *testing.T, id, re string) string {
	t.Helper()
	rx := regexp.MustCompile(re)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if m := rx.FindStringSubmatch(r.stream(id, "stdout")); m != nil {
			return m[len(m)-1]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("stdout never matched %q: %q (stderr %q)", re, r.stream(id, "stdout"), r.stream(id, "stderr"))
	return ""
}

type liveEnv struct {
	rec  *liveRecorder
	m    *jobs.Manager
	tmp  string
	plat platform.Platform
	n    atomic.Int64
}

// tempBase returns a scratch directory. The agent's own temp directory
// (C:\ProgramData\DranzoRMM\tmp) has no spaces; a user TEMP with a space
// would change how cmd.exe parses "/C <script>", so it is avoided here and
// reported.
func tempBase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if !strings.ContainsRune(dir, ' ') {
		return dir
	}
	t.Logf("NOTE: the test temp directory %q contains a space; using %%ProgramData%% instead", dir)
	alt, err := os.MkdirTemp(os.Getenv("ProgramData"), "dranzo-kit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(alt) })
	return alt
}

func newLiveEnv(t *testing.T, plat platform.Platform) *liveEnv {
	t.Helper()
	e := &liveEnv{rec: &liveRecorder{out: map[string]*strings.Builder{}, res: map[string]protocol.JobResult{}}, plat: plat}
	e.tmp = filepath.Join(tempBase(t), "tmp")
	e.m = jobs.NewManager(context.Background(), jobs.Options{
		DeviceID: "dev-1", Sender: e.rec, Platform: plat, TempDir: e.tmp,
		Logger: logging.NewWithWriter(os.Stderr, slog.LevelWarn), FlushInterval: 20 * time.Millisecond,
	})
	e.m.Register(protocol.KindScript, New())
	t.Cleanup(func() { e.m.Shutdown(10 * time.Second) })
	return e
}

func (e *liveEnv) dispatch(t *testing.T, spec protocol.ScriptSpec, timeout int) string {
	t.Helper()
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", e.n.Add(1))
	raw, _ := json.Marshal(spec)
	if err := e.m.Dispatch(context.Background(), protocol.JobDispatch{
		JobRunID: id, Kind: protocol.KindScript, TimeoutSeconds: timeout, Spec: raw,
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *liveEnv) noLeftovers(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(e.tmp)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, de := range entries {
			names = append(names, de.Name())
		}
		t.Errorf("script temp directories left behind: %v", names)
	}
}

func exitCode(r protocol.JobResult) string {
	if r.ExitCode == nil {
		return "nil"
	}
	return strconv.Itoa(*r.ExitCode)
}

func TestWindowsLivePowerShellScript(t *testing.T) {
	requireLiveWindows(t)
	e := newLiveEnv(t, platform.New())
	body := "param([string]$First, [string]$Second)\r\n" +
		"Write-Output ('first=' + $First)\r\n" +
		"Write-Output ('second=' + $Second)\r\n" +
		"Write-Output ('env=' + $env:DZ_LIVE_VAR)\r\n" +
		"Write-Output ('ps=' + $PSVersionTable.PSVersion.Major)\r\n" +
		"[Console]::Error.WriteLine('err-line')\r\n" +
		"exit 7\r\n"
	id := e.dispatch(t, protocol.ScriptSpec{
		Language: protocol.LangPowerShell, Body: body,
		Args: []string{"a b", `c"d`}, Env: map[string]string{"DZ_LIVE_VAR": "v 1"},
	}, 120)
	res := e.rec.wait(t, id, 2*time.Minute)
	out, errOut := e.rec.stream(id, "stdout"), e.rec.stream(id, "stderr")
	t.Logf("status=%s exit=%s message=%q\nstdout=%q\nstderr=%q", res.Status, exitCode(res), res.Message, out, errOut)
	if res.Status != protocol.StatusFailed || res.ExitCode == nil || *res.ExitCode != 7 {
		t.Errorf("status %s exit %s, want failed / 7", res.Status, exitCode(res))
	}
	for _, want := range []string{"first=a b\r\n", "second=c\"d\r\n", "env=v 1\r\n", "ps=5\r\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q", want)
		}
	}
	if !strings.Contains(errOut, "err-line") {
		t.Errorf("stderr lacks err-line")
	}

	// Success, and the encoding of non-ASCII output (recorded, not asserted:
	// Windows PowerShell writes redirected output in the OEM code page).
	id = e.dispatch(t, protocol.ScriptSpec{Language: protocol.LangPowerShell, Body: "Write-Output 'ok-\u00fc\u00e9'\r\n"}, 120)
	res = e.rec.wait(t, id, 2*time.Minute)
	out = e.rec.stream(id, "stdout")
	if res.Status != protocol.StatusSucceeded || !strings.HasPrefix(out, "ok-") {
		t.Errorf("simple script: %s exit %s %q", res.Status, exitCode(res), out)
	}
	t.Logf("RESULT non-ASCII output: %q (want %q)", out, "ok-\u00fc\u00e9\r\n")
	e.noLeftovers(t)
}

func TestWindowsLiveCmdScript(t *testing.T) {
	requireLiveWindows(t)
	e := newLiveEnv(t, platform.New())
	body := "@echo off\r\necho out:%1 %2\r\necho env:%DZ_LIVE_VAR%\r\necho err-line 1>&2\r\nexit /b 3\r\n"
	id := e.dispatch(t, protocol.ScriptSpec{
		Language: protocol.LangCmd, Body: body, Args: []string{"hello", "two words"},
		Env: map[string]string{"DZ_LIVE_VAR": "x"},
	}, 120)
	res := e.rec.wait(t, id, 2*time.Minute)
	out, errOut := e.rec.stream(id, "stdout"), e.rec.stream(id, "stderr")
	t.Logf("status=%s exit=%s message=%q\nstdout=%q\nstderr=%q", res.Status, exitCode(res), res.Message, out, errOut)
	if res.Status != protocol.StatusFailed || res.ExitCode == nil || *res.ExitCode != 3 {
		t.Errorf("status %s exit %s, want failed / 3", res.Status, exitCode(res))
	}
	if !strings.Contains(out, `out:hello "two words"`) || !strings.Contains(out, "env:x") {
		t.Errorf("stdout %q", out)
	}
	if !strings.Contains(errOut, "err-line") {
		t.Errorf("stderr %q", errOut)
	}

	// Arguments cmd.exe would interpret are refused before anything runs.
	id = e.dispatch(t, protocol.ScriptSpec{Language: protocol.LangCmd, Body: "@echo off\r\necho %1\r\n", Args: []string{"a&calc"}}, 60)
	if res := e.rec.wait(t, id, time.Minute); res.Status != protocol.StatusRejected {
		t.Errorf("dangerous cmd argument: %s %q", res.Status, res.Message)
	}
	e.noLeftovers(t)
}

// treeScript starts ping.exe as a child and waits for it; it prints both pids.
const treeScript = "$p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\\PING.EXE') -ArgumentList '-n','120','127.0.0.1' -NoNewWindow -PassThru\r\n" +
	"[Console]::Out.WriteLine('shell=' + $PID + '=')\r\n" +
	"[Console]::Out.WriteLine('child=' + $p.Id + '=')\r\n" +
	"[Console]::Out.Flush()\r\n" +
	"Wait-Process -Id $p.Id\r\n"

func TestWindowsLiveScriptTimeoutKillsTree(t *testing.T) {
	requireLiveWindows(t)
	e := newLiveEnv(t, platform.New())
	start := time.Now()
	id := e.dispatch(t, protocol.ScriptSpec{Language: protocol.LangPowerShell, Body: treeScript}, 15)
	shell := e.rec.awaitStdout(t, id, `shell=(\d+)=`)
	child := e.rec.awaitStdout(t, id, `child=(\d+)=`)
	sp, _ := strconv.Atoi(shell)
	cp, _ := strconv.Atoi(child)
	if !processAlive(cp) {
		t.Fatalf("ping child %d is not running before the timeout", cp)
	}
	res := e.rec.wait(t, id, 2*time.Minute)
	t.Logf("status=%s after %v message=%q", res.Status, time.Since(start).Round(time.Millisecond), res.Message)
	if res.Status != protocol.StatusTimeout {
		t.Errorf("status %s, want timeout", res.Status)
	}
	waitGone(t, "powershell", sp)
	waitGone(t, "ping child", cp)
	e.noLeftovers(t)
}

func TestWindowsLiveScriptCancelKillsTree(t *testing.T) {
	requireLiveWindows(t)
	e := newLiveEnv(t, platform.New())
	id := e.dispatch(t, protocol.ScriptSpec{Language: protocol.LangPowerShell, Body: treeScript}, 300)
	cp, _ := strconv.Atoi(e.rec.awaitStdout(t, id, `child=(\d+)=`))
	if !e.m.Cancel(id) {
		t.Fatal("cancel not accepted")
	}
	res := e.rec.wait(t, id, 2*time.Minute)
	if res.Status != protocol.StatusCancelled {
		t.Errorf("status %s, want cancelled", res.Status)
	}
	waitGone(t, "ping child", cp)
	e.noLeftovers(t)
}

func TestWindowsLiveRequireSignedPowerShell(t *testing.T) {
	requireLiveWindows(t)
	e := newLiveEnv(t, platform.New())
	id := e.dispatch(t, protocol.ScriptSpec{
		Language: protocol.LangPowerShell, Body: "Write-Output 'unsigned-ran'\r\n", RequireSignedPowerShell: true,
	}, 120)
	res := e.rec.wait(t, id, 2*time.Minute)
	out, errOut := e.rec.stream(id, "stdout"), e.rec.stream(id, "stderr")
	t.Logf("status=%s exit=%s\nstdout=%q\nstderr=%q", res.Status, exitCode(res), out, errOut)
	if res.Status == protocol.StatusSucceeded || strings.Contains(out, "unsigned-ran") {
		t.Errorf("an unsigned script ran under AllSigned")
	}
	if !strings.Contains(strings.ToLower(errOut+out), "signed") {
		t.Logf("NOTE: the error does not mention signing")
	}
	// The same script without the requirement runs.
	id = e.dispatch(t, protocol.ScriptSpec{Language: protocol.LangPowerShell, Body: "Write-Output 'unsigned-ran'\r\n"}, 120)
	if res := e.rec.wait(t, id, 2*time.Minute); res.Status != protocol.StatusSucceeded {
		t.Errorf("unsigned script without the requirement: %s", res.Status)
	}
	e.noLeftovers(t)
}

func TestWindowsLivePython(t *testing.T) {
	requireLiveWindows(t)
	interp, err := resolveInterpreter(protocol.LangPython, false)
	if err != nil {
		t.Skipf("RESULT python: %v", err)
	}
	t.Logf("python interpreter: %s %v", interp.path, interp.prefix)
	if strings.Contains(strings.ToLower(interp.path), `\microsoft\windowsapps\`) {
		// The Microsoft Store "App execution alias" stub is found on PATH
		// even when Python is not installed; running it prints an install hint.
		cmd := exec.Command(interp.path, "--version")
		out, rerr := cmd.CombinedOutput()
		t.Logf("RESULT python: WindowsApps alias %s -> %q (%v)", interp.path, strings.TrimSpace(string(out)), rerr)
		if rerr != nil {
			t.Skip("only the Microsoft Store alias stub is present (the agent would report python as available and fail at run time)")
		}
	}
	e := newLiveEnv(t, platform.New())
	id := e.dispatch(t, protocol.ScriptSpec{
		Language: protocol.LangPython, Body: "import sys\nprint('py', sys.argv[1])\nsys.exit(4)\n", Args: []string{"arg"},
	}, 120)
	res := e.rec.wait(t, id, 2*time.Minute)
	out := e.rec.stream(id, "stdout")
	t.Logf("status=%s exit=%s stdout=%q stderr=%q", res.Status, exitCode(res), out, e.rec.stream(id, "stderr"))
	if res.Status != protocol.StatusFailed || res.ExitCode == nil || *res.ExitCode != 4 || strings.TrimSpace(out) != "py arg" {
		t.Errorf("python script: %s exit %s %q", res.Status, exitCode(res), out)
	}
}

// TestWindowsLiveRunAsUser runs a script in the console user's session. It
// needs LocalSystem (WTSQueryUserToken) and a logged-in user: run the kit
// with -AsSystem while someone is signed in at the console.
func TestWindowsLiveRunAsUser(t *testing.T) {
	requireLiveWindows(t)
	plat := platform.New()
	u, err := plat.ConsoleUser(context.Background())
	if !runningAsSystem() {
		t.Logf("console user lookup as non-SYSTEM: %+v %v", u, err)
		t.Skip("runAs user needs LocalSystem (run the kit with -AsSystem)")
	}
	if errors.Is(err, platform.ErrNoConsoleUser) {
		t.Skip("nobody is logged in at the console")
	}
	if err != nil {
		t.Fatalf("console user: %v", err)
	}
	t.Logf("console user: %+v", *u)
	e := newLiveEnv(t, plat)
	id := e.dispatch(t, protocol.ScriptSpec{
		Language: protocol.LangPowerShell, RunAs: protocol.RunAsUser,
		Body: "Write-Output ('user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + '=')\r\nWrite-Output ('session=' + (Get-Process -Id $PID).SessionId + '=')\r\n",
	}, 120)
	res := e.rec.wait(t, id, 2*time.Minute)
	out := e.rec.stream(id, "stdout")
	t.Logf("status=%s stdout=%q stderr=%q", res.Status, out, e.rec.stream(id, "stderr"))
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("status %s %q", res.Status, res.Message)
	}
	if !strings.Contains(strings.ToLower(out), "user="+strings.ToLower(u.Name)+"=") {
		t.Errorf("script did not run as %s: %q", u.Name, out)
	}
	if !strings.Contains(out, fmt.Sprintf("session=%d=", u.SessionID)) {
		t.Errorf("script did not run in session %d: %q", u.SessionID, out)
	}
}
