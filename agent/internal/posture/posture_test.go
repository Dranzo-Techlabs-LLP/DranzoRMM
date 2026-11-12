package posture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// reply is the canned result of one command.
type reply struct {
	stdout, stderr string
	code           int
	err            error
}

// fakeSystem replaces the collector's access to the machine.
type fakeSystem struct {
	mu      sync.Mutex
	replies map[string]reply // "path arg1 arg2" -> result
	scripts map[string]reply // stdin text (PowerShell script) -> result
	files   map[string]string
	tools   map[string]string // tool name -> path
	procs   []string
	calls   []platform.Command
}

func (f *fakeSystem) run(_ context.Context, cmd platform.Command) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	r, ok := f.replies[strings.Join(append([]string{cmd.Path}, cmd.Args...), " ")]
	if cmd.Stdin != nil {
		in, _ := io.ReadAll(cmd.Stdin)
		r, ok = f.scripts[string(in)]
	}
	f.mu.Unlock()
	if !ok {
		return platform.ExitCodeUnknown, errors.New("fake: command not expected: " + cmd.Path + " " + strings.Join(cmd.Args, " "))
	}
	if r.err != nil {
		return platform.ExitCodeUnknown, r.err
	}
	if cmd.Stdout != nil {
		_, _ = io.WriteString(cmd.Stdout, r.stdout)
	}
	if cmd.Stderr != nil {
		_, _ = io.WriteString(cmd.Stderr, r.stderr)
	}
	return r.code, nil
}

// collector builds a Collector whose every access goes to the fake.
func (f *fakeSystem) collector(plat *platform.Fake) *Collector {
	plat.RunFunc = f.run
	c := New(plat, nil)
	c.sys.look = func(names ...string) string {
		for _, n := range names {
			if p := f.tools[n]; p != "" {
				return p
			}
		}
		return ""
	}
	c.sys.read = func(path string, limit int) ([]byte, error) {
		s, ok := f.files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		if len(s) > limit {
			s = s[:limit]
		}
		return []byte(s), nil
	}
	c.sys.exists = func(path string) bool { _, ok := f.files[path]; return ok }
	c.sys.procs = func(context.Context) ([]string, error) { return f.procs, nil }
	c.sys.now = func() time.Time { return fixedNow }
	c.sys.euid = func() int { return 0 }
	return c
}

func TestUnsupportedError(t *testing.T) {
	err := Unsupportedf("no %s", "BitLocker")
	if err.Error() != "not supported on this OS: no BitLocker" || !errors.Is(err, platform.ErrUnsupported) {
		t.Errorf("%v", err)
	}
	var ue *UnsupportedError
	if !errors.As(err, &ue) || ue.Reason != "no BitLocker" {
		t.Errorf("%+v", ue)
	}
}

func TestExec(t *testing.T) {
	big := strings.Repeat("x", 3000)
	plat := &platform.Fake{RunFunc: func(_ context.Context, cmd platform.Command) (int, error) {
		if cmd.Stdin != nil {
			in, _ := io.ReadAll(cmd.Stdin)
			_, _ = cmd.Stdout.Write(in)
		}
		_, _ = io.WriteString(cmd.Stdout, big)
		_, _ = io.WriteString(cmd.Stderr, "warning\n")
		return 3, nil
	}}
	e := Exec{Platform: plat}
	res, err := e.Run(context.Background(), Cmd{Path: "/bin/tool", Stdin: "in:", MaxStdout: 1000})
	if err != nil || res.ExitCode != 3 || len(res.Stdout) != 1000 || !strings.HasPrefix(res.Stdout, "in:xxx") || res.Stderr != "warning\n" {
		t.Errorf("%d %d %q %v", res.ExitCode, len(res.Stdout), res.Stderr, err)
	}
	// Output: a non-zero exit code is an error that carries stderr.
	if _, err := e.Output(context.Background(), Cmd{Path: "/bin/tool"}); err == nil || !strings.Contains(err.Error(), "exit code 3: warning") {
		t.Errorf("%v", err)
	}
	if _, err := e.Run(context.Background(), Cmd{}); err == nil {
		t.Error("empty path accepted")
	}
	// The timeout reaches the platform as a context deadline.
	plat.RunFunc = func(ctx context.Context, _ platform.Command) (int, error) {
		<-ctx.Done()
		return platform.ExitCodeUnknown, ctx.Err()
	}
	start := time.Now()
	if _, err := e.Run(context.Background(), Cmd{Path: "/bin/sleep", Timeout: 50 * time.Millisecond}); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Errorf("timeout: %v", err)
	}
}

func TestOneLine(t *testing.T) {
	if got := OneLine("  a\r\n\tb\x00c\x1b[31m  ", 100); got != "a bc[31m" {
		t.Errorf("%q", got)
	}
	if got := OneLine(strings.Repeat("é", 10), 5); got != "éé..." {
		t.Errorf("%q", got)
	}
	if got := OneLine("bad \xff utf8", 100); got != "bad ? utf8" {
		t.Errorf("%q", got)
	}
}

func TestLookTool(t *testing.T) {
	if p := LookTool("../../etc/passwd", "a/b", ""); p != "" {
		t.Errorf("path-like name accepted: %q", p)
	}
	if p := LookTool("dranzo-no-such-tool"); p != "" {
		t.Errorf("%q", p)
	}
}

// TestCollectShape runs the real collector of this OS with every command
// failing and checks the invariants of the report: it never fails, a section
// is either filled or listed in "unsupported", and the JSON has the fields of
// PROTOCOL.md section 7.3.
func TestCollectShape(t *testing.T) {
	plat := &platform.Fake{
		PendingErr: platform.ErrUnsupported,
		ConsoleErr: platform.ErrNoConsoleUser,
		RunFunc: func(context.Context, platform.Command) (int, error) {
			return platform.ExitCodeUnknown, errors.New("commands are disabled in this test")
		},
	}
	c := New(plat, nil)
	c.sys.now = func() time.Time { return fixedNow }
	p := c.Collect(context.Background())

	missing := map[string]bool{}
	for _, s := range p.Unsupported {
		if missing[s] {
			t.Errorf("%s listed twice", s)
		}
		missing[s] = true
	}
	check := func(section string, filled bool) {
		if filled == missing[section] {
			t.Errorf("%s: filled=%v, listed as unsupported=%v", section, filled, missing[section])
		}
	}
	check(SectionAntivirus, p.Antivirus != nil)
	check(SectionFirewall, p.Firewall != nil)
	check(SectionDiskEncryption, p.DiskEncryption != nil)
	check(SectionLocalAdmins, p.LocalAdmins != nil)
	check(SectionScreenLock, p.ScreenLock != nil)
	check(SectionLastPatchDate, p.LastPatchDate != nil)
	check(SectionListeningPorts, p.ListeningPorts != nil)
	if !missing[SectionPendingReboot] || p.PendingReboot {
		t.Errorf("pendingReboot: %v %v", p.PendingReboot, p.Unsupported)
	}
	if !p.CollectedAt.Equal(fixedNow) {
		t.Errorf("collectedAt %v", p.CollectedAt)
	}

	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"collectedAt", "antivirus", "firewall", "diskEncryption", "localAdmins", "screenLock", "lastPatchDate", "pendingReboot", "listeningPorts", "unsupported"} {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON lacks %q: %s", key, raw)
		}
	}
	// A section that is not supported is JSON null, never an empty value.
	for section := range missing {
		if section != SectionPendingReboot && string(m[section]) != "null" {
			t.Errorf("%s is unsupported but not null: %s", section, m[section])
		}
	}
	if string(m["unsupported"]) == "null" {
		t.Errorf("unsupported must be a list: %s", raw)
	}
}

func TestReporter(t *testing.T) {
	plat := &platform.Fake{RunFunc: func(context.Context, platform.Command) (int, error) {
		return platform.ExitCodeUnknown, errors.New("disabled")
	}}
	msgType, payload, err := Reporter(New(plat, nil))(context.Background())
	if err != nil || msgType != "posture" || payload == nil {
		t.Errorf("%q %v %v", msgType, payload, err)
	}
}
