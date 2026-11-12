//go:build !windows

package script

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

type recorder struct {
	mu   sync.Mutex
	out  map[string]*strings.Builder
	res  map[string]protocol.JobResult
	acks map[string]protocol.JobAck
}

func newRecorder() *recorder {
	return &recorder{out: map[string]*strings.Builder{}, res: map[string]protocol.JobResult{}, acks: map[string]protocol.JobAck{}}
}

func (r *recorder) Send(_ context.Context, typ string, payload any) error {
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
	case protocol.JobAck:
		r.acks[p.JobRunID] = p
	}
	_ = typ
	return nil
}

func (r *recorder) stream(id, stream string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b := r.out[id+"/"+stream]; b != nil {
		return b.String()
	}
	return ""
}

func (r *recorder) wait(t *testing.T, id string, timeout time.Duration) protocol.JobResult {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		res, ok := r.res[id]
		r.mu.Unlock()
		if ok {
			return res
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no result for %s", id)
	return protocol.JobResult{}
}

type env struct {
	t    *testing.T
	rec  *recorder
	m    *jobs.Manager
	fake *platform.Fake
	tmp  string
	n    int
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newEnv(t *testing.T) (*env, *lockedBuffer) {
	t.Helper()
	logs := &lockedBuffer{}
	e := &env{t: t, rec: newRecorder(), fake: &platform.Fake{}, tmp: filepath.Join(t.TempDir(), "tmp")}
	e.m = jobs.NewManager(context.Background(), jobs.Options{
		DeviceID: "dev-1", Sender: e.rec, Platform: e.fake, TempDir: e.tmp,
		Logger: logging.NewWithWriter(logs, slog.LevelDebug), FlushInterval: 10 * time.Millisecond,
	})
	e.m.Register(protocol.KindScript, New())
	t.Cleanup(func() { e.m.Shutdown(5 * time.Second) })
	return e, logs
}

func (e *env) dispatch(spec protocol.ScriptSpec, timeout int) string {
	e.t.Helper()
	e.n++
	id := "00000000-0000-4000-8000-" + strings.Repeat("0", 11) + string(rune('0'+e.n))
	raw, _ := json.Marshal(spec)
	if err := e.m.Dispatch(context.Background(), protocol.JobDispatch{
		JobRunID: id, Kind: protocol.KindScript, TimeoutSeconds: timeout, Spec: raw,
	}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestScriptStdoutStderrExitCodeArgsEnv(t *testing.T) {
	e, logs := newEnv(t)
	const body = `echo "out:$1:$2:$GREETING"
echo "problem here" 1>&2
exit 7
`
	id := e.dispatch(protocol.ScriptSpec{
		Language: "sh", Body: body, RunAs: "system",
		Args: []string{"first arg", `$(touch /tmp/dranzo-injected); echo "x"`},
		Env:  map[string]string{"GREETING": "hello world"},
	}, 30)
	res := e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusFailed || res.ExitCode == nil || *res.ExitCode != 7 {
		t.Fatalf("result %+v", res)
	}
	// Arguments arrive verbatim as argv: nothing is interpreted by a shell.
	wantOut := "out:first arg:$(touch /tmp/dranzo-injected); echo \"x\":hello world\n"
	if got := e.rec.stream(id, "stdout"); got != wantOut {
		t.Fatalf("stdout %q", got)
	}
	if got := e.rec.stream(id, "stderr"); got != "problem here\n" {
		t.Fatalf("stderr %q", got)
	}
	if res.OutputBytes != int64(len(wantOut)+len("problem here\n")) {
		t.Fatalf("outputBytes %d", res.OutputBytes)
	}
	if left := tempLeftovers(t, e.tmp); len(left) != 0 {
		t.Fatalf("script temp files not cleaned up: %v", left)
	}
	// The log has the hash of the body, never the body, arguments or env values.
	l := logs.String()
	if !strings.Contains(l, "script_sha256") || !strings.Contains(l, `"job_run_id":"`+id+`"`) || !strings.Contains(l, `"device_id":"dev-1"`) {
		t.Fatalf("log lacks hash / correlation ids: %s", l)
	}
	for _, secret := range []string{"problem here", "hello world", "first arg", "dranzo-injected"} {
		if strings.Contains(l, secret) {
			t.Fatalf("log contains script content %q", secret)
		}
	}
}

func TestScriptSuccessAndLanguages(t *testing.T) {
	e, _ := newEnv(t)
	id := e.dispatch(protocol.ScriptSpec{Language: "sh", Body: "echo ok"}, 30)
	if res := e.rec.wait(t, id, 20*time.Second); res.Status != protocol.StatusSucceeded || *res.ExitCode != 0 {
		t.Fatalf("%+v", res)
	}
	if _, err := exec.LookPath("bash"); err == nil {
		id = e.dispatch(protocol.ScriptSpec{Language: "bash", Body: `arr=(a b c); echo "${#arr[@]}"`}, 30)
		if res := e.rec.wait(t, id, 20*time.Second); res.Status != protocol.StatusSucceeded || e.rec.stream(id, "stdout") != "3\n" {
			t.Fatalf("bash: %+v %q", res, e.rec.stream(id, "stdout"))
		}
	}
	if _, err := exec.LookPath("python3"); err == nil {
		id = e.dispatch(protocol.ScriptSpec{Language: "python", Body: "import sys\nprint('py', sys.argv[1])\nsys.exit(4)\n", Args: []string{"arg"}}, 60)
		res := e.rec.wait(t, id, 40*time.Second)
		if res.Status != protocol.StatusFailed || *res.ExitCode != 4 || e.rec.stream(id, "stdout") != "py arg\n" {
			t.Fatalf("python: %+v %q", res, e.rec.stream(id, "stdout"))
		}
	}
}

func TestScriptUnsupportedOnThisOS(t *testing.T) {
	e, _ := newEnv(t)
	id := e.dispatch(protocol.ScriptSpec{Language: "cmd", Body: "echo hi"}, 30)
	res := e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusUnsupported || !strings.HasPrefix(res.Message, "not supported on this OS: ") {
		t.Fatalf("cmd: %+v", res)
	}
	id = e.dispatch(protocol.ScriptSpec{Language: "powershell", Body: "Write-Output hi", RequireSignedPowerShell: true}, 30)
	res = e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusUnsupported || !strings.Contains(res.Message, "Windows") {
		t.Fatalf("requireSignedPowerShell: %+v", res)
	}
	if _, err := exec.LookPath("pwsh"); err != nil {
		id = e.dispatch(protocol.ScriptSpec{Language: "powershell", Body: "Write-Output hi"}, 30)
		res = e.rec.wait(t, id, 20*time.Second)
		if res.Status != protocol.StatusUnsupported || !strings.Contains(res.Message, "pwsh") {
			t.Fatalf("powershell without pwsh: %+v", res)
		}
	}
}

func TestScriptRejectedSpec(t *testing.T) {
	e, _ := newEnv(t)
	id := e.dispatch(protocol.ScriptSpec{Language: "sh", Body: "echo hi", Env: map[string]string{"BAD NAME": "x"}}, 30)
	if res := e.rec.wait(t, id, 20*time.Second); res.Status != protocol.StatusRejected {
		t.Fatalf("%+v", res)
	}
	if e.rec.stream(id, "stdout") != "" {
		t.Fatal("a rejected script produced output")
	}
}

func pidAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func waitGone(pid int) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if !pidAlive(pid) {
			return true
		}
	}
	return false
}

func childPid(t *testing.T, e *env, id string) int {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if out := e.rec.stream(id, "stdout"); strings.Contains(out, "\n") {
			var pid int
			for _, c := range strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]) {
				pid = pid*10 + int(c-'0')
			}
			return pid
		}
	}
	t.Fatal("script did not report its child pid")
	return 0
}

// The script starts a grandchild; timeout and cancel must kill the whole tree.
const treeScript = `sleep 300 &
echo $!
wait
`

func TestScriptTimeoutKillsProcessTree(t *testing.T) {
	e, _ := newEnv(t)
	start := time.Now()
	id := e.dispatch(protocol.ScriptSpec{Language: "sh", Body: treeScript}, 1)
	pid := childPid(t, e, id)
	res := e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusTimeout {
		t.Fatalf("expected timeout, got %+v", res)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	if !waitGone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d survived the timeout", pid)
	}
	if left := tempLeftovers(t, e.tmp); len(left) != 0 {
		t.Fatalf("temp files left after timeout: %v", left)
	}
}

func TestScriptCancelKillsProcessTree(t *testing.T) {
	e, _ := newEnv(t)
	id := e.dispatch(protocol.ScriptSpec{Language: "sh", Body: treeScript}, 120)
	pid := childPid(t, e, id)
	if !e.m.Cancel(id) {
		t.Fatal("job not found for cancel")
	}
	res := e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusCancelled {
		t.Fatalf("expected cancelled, got %+v", res)
	}
	if !waitGone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d survived the cancel", pid)
	}
}

func TestScriptOutputCap(t *testing.T) {
	e, _ := newEnv(t)
	raw, _ := json.Marshal(protocol.ScriptSpec{Language: "sh", Body: "i=0; while [ $i -lt 4000 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done"})
	id := "00000000-0000-4000-8000-0000000000aa"
	_ = e.m.Dispatch(context.Background(), protocol.JobDispatch{JobRunID: id, Kind: protocol.KindScript, TimeoutSeconds: 60, MaxOutputBytes: 20000, Spec: raw})
	res := e.rec.wait(t, id, 40*time.Second)
	if res.Status != protocol.StatusSucceeded || !res.Truncated || res.OutputBytes != 20000 {
		t.Fatalf("%+v", res)
	}
	if got := len(e.rec.stream(id, "stdout")); got != 20000 {
		t.Fatalf("delivered %d bytes", got)
	}
}

func TestScriptRunAsUser(t *testing.T) {
	e, _ := newEnv(t)
	// Nobody logged in.
	id := e.dispatch(protocol.ScriptSpec{Language: "sh", Body: "echo hi", RunAs: "user"}, 30)
	res := e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusFailed || res.Message != "no logged-in user" {
		t.Fatalf("no console user: %+v", res)
	}
	// With a console user the command is handed to the platform's run-as-user
	// path and the script is granted to that user (the fake runs it as us).
	e.fake.User = &platform.User{Name: "alice", UID: "501", GID: "20"}
	e.fake.IgnoreAsUser = true
	id = e.dispatch(protocol.ScriptSpec{Language: "sh", Body: "echo as-user", RunAs: "user"}, 30)
	res = e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusSucceeded || e.rec.stream(id, "stdout") != "as-user\n" {
		t.Fatalf("%+v %q", res, e.rec.stream(id, "stdout"))
	}
	if e.fake.RanAsUser != 1 || len(e.fake.Granted) != 2 {
		t.Fatalf("run-as-user path not used: ran=%d granted=%v", e.fake.RanAsUser, e.fake.Granted)
	}
	// File first, then the directory.
	if !strings.HasSuffix(e.fake.Granted[0], "script.sh") || filepath.Dir(e.fake.Granted[0]) != e.fake.Granted[1] {
		t.Fatalf("grant order: %v", e.fake.Granted)
	}
	if _, err := os.Stat(e.fake.Granted[1]); !os.IsNotExist(err) {
		t.Fatal("user script directory not cleaned up")
	}
}

func TestScriptFileIsOwnerOnly(t *testing.T) {
	e, _ := newEnv(t)
	id := e.dispatch(protocol.ScriptSpec{Language: "sh", Body: `d=$(dirname "$0"); ls -ld "$d" | cut -c1-10; ls -l "$0" | cut -c1-10`}, 30)
	res := e.rec.wait(t, id, 20*time.Second)
	if res.Status != protocol.StatusSucceeded {
		t.Fatalf("%+v", res)
	}
	if got := e.rec.stream(id, "stdout"); got != "drwx------\n-rwx------\n" {
		t.Fatalf("permissions: %q", got)
	}
}
