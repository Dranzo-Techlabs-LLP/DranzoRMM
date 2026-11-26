//go:build !windows

package mesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

// These tests install a stand-in "meshagent": a shell script that behaves
// like the real binary for the three switches the handlers use. They prove
// the download / verify / execute / parse flow, NOT compatibility with a
// real MeshAgent build or MeshCentral server.

// fakeAgentScript returns the stand-in binary. It records every invocation
// in <root>/calls, "installs" itself to <root>/installed/meshagent and
// prints the node id found in <root>/nodeid.
func fakeAgentScript(root string, installExit int) []byte {
	return []byte(fmt.Sprintf(`#!/bin/sh
root=%q
echo "$0 $*" >> "$root/calls"
case "$1" in
-fullinstall)
	if [ %d -ne 0 ]; then echo "install failed: service manager not available"; exit %d; fi
	mkdir -p "$root/installed" && cp "$0" "$root/installed/meshagent" && chmod 700 "$root/installed/meshagent"
	msh="$(dirname "$0")/meshagent.msh"
	if [ -f "$msh" ]; then cp "$msh" "$root/msh-at-install"; fi
	if [ -f "$root/copy-msh" ] && [ -f "$msh" ]; then cp "$msh" "$root/installed/meshagent.msh"; fi
	echo "...Installing service [meshagent]"
	echo "   -> SERVICE: meshagent [RUNNING]"
	;;
-nodeid)
	if [ -f "$root/nodeid-after" ]; then
		n=$(cat "$root/nodeid-after"); n=$((n-1)); echo $n > "$root/nodeid-after"
		if [ $n -ge 0 ]; then exit 0; fi
	fi
	[ -f "$root/nodeid" ] && cat "$root/nodeid"
	exit 0
	;;
-fulluninstall)
	rm -rf "$root/installed"
	echo "Mesh agent was uninstalled"
	;;
*)
	echo "unexpected arguments: $*"; exit 64
	;;
esac
`, root, installExit, installExit))
}

type blobs struct {
	mu        sync.Mutex
	content   map[string][]byte
	downloads int
}

func (b *blobs) add(data []byte) (id, sum string) {
	id = protocol.NewID()
	h := sha256.Sum256(data)
	b.mu.Lock()
	b.content[id] = data
	b.mu.Unlock()
	return id, hex.EncodeToString(h[:])
}

func (b *blobs) Download(context.Context, string, io.Writer, int64, string) error {
	return errors.New("not used")
}

func (b *blobs) Upload(context.Context, string, io.Reader, int64) error {
	return errors.New("not used")
}

// DownloadFile behaves like transport.BlobClient: exclusive create, verify,
// remove on mismatch.
func (b *blobs) DownloadFile(_ context.Context, blobID, destPath string, sizeBytes int64, sha256Hex string) error {
	b.mu.Lock()
	data, ok := b.content[blobID]
	b.downloads++
	b.mu.Unlock()
	if !ok {
		return errors.New("download blob: HTTP status 404")
	}
	if err := os.WriteFile(destPath, data, 0o600); err != nil {
		return err
	}
	if int64(len(data)) != sizeBytes {
		_ = os.Remove(destPath)
		return transport.ErrSizeMismatch
	}
	if h := sha256.Sum256(data); hex.EncodeToString(h[:]) != sha256Hex {
		_ = os.Remove(destPath)
		return transport.ErrHashMismatch
	}
	return nil
}

type env struct {
	t     *testing.T
	root  string
	opts  Options
	blobs *blobs
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	return &env{
		t:     t,
		root:  root,
		blobs: &blobs{content: map[string][]byte{}},
		opts: Options{
			Dir:            filepath.Join(root, "state", DirName),
			InstalledPaths: []string{filepath.Join(root, "installed", "meshagent")},
			NodeIDAttempts: 4,
			NodeIDDelay:    10 * time.Millisecond,
		},
	}
}

func (e *env) run(h jobs.Handler, spec any) jobs.Result {
	e.t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		e.t.Fatal(err)
	}
	return h.Handle(&jobs.JobContext{
		Ctx: context.Background(), JobRunID: protocol.NewID(), Spec: raw,
		Blobs: e.blobs, Platform: &platform.Fake{}, Stdout: io.Discard, Stderr: io.Discard,
	})
}

func (e *env) calls() []string {
	data, err := os.ReadFile(filepath.Join(e.root, "calls"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func (e *env) installSpec(script []byte) protocol.MeshInstallSpec {
	id, sum := e.blobs.add(script)
	return protocol.MeshInstallSpec{BlobID: id, SHA256: sum, SizeBytes: int64(len(script)), FileName: "meshagent"}
}

func meshResult(t *testing.T, r jobs.Result) protocol.MeshResult {
	t.Helper()
	res, ok := r.Result.(protocol.MeshResult)
	if !ok {
		t.Fatalf("result type %T (status %s: %s)", r.Result, r.Status, r.Message)
	}
	return res
}

func TestInstallAndUninstall(t *testing.T) {
	e := newEnv(t)
	if err := os.WriteFile(filepath.Join(e.root, "nodeid"), []byte(sampleNodeID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := e.run(Install(e.opts), e.installSpec(fakeAgentScript(e.root, 0)))
	if r.Status != protocol.StatusSucceeded {
		t.Fatalf("status = %s (%s)", r.Status, r.Message)
	}
	if res := meshResult(t, r); !res.Installed || res.MeshNodeID != "node//"+sampleNodeID {
		t.Errorf("result = %+v", res)
	}

	// The binary sits in a root-only directory, executable by its owner only.
	binary := filepath.Join(e.opts.Dir, "meshagent")
	if fi, err := os.Stat(binary); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("binary mode = %v, %v", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(e.opts.Dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %v, %v", fi.Mode().Perm(), err)
	}
	if entries, _ := os.ReadDir(e.opts.Dir); len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	// Exactly the documented commands, with no further arguments: nothing
	// that would rename or hide the MeshAgent service.
	calls := e.calls()
	installed := e.opts.InstalledPaths[0]
	if len(calls) != 2 || calls[0] != binary+" -fullinstall" || calls[1] != installed+" -nodeid" {
		t.Errorf("commands run:\n%s", strings.Join(calls, "\n"))
	}

	r = e.run(Uninstall(e.opts), struct{}{})
	if r.Status != protocol.StatusSucceeded {
		t.Fatalf("uninstall status = %s (%s)", r.Status, r.Message)
	}
	if res := meshResult(t, r); res.Installed || res.MeshNodeID != "" {
		t.Errorf("uninstall result = %+v", res)
	}
	calls = e.calls()
	if last := calls[len(calls)-1]; last != installed+" -fulluninstall" {
		t.Errorf("uninstall command = %q", last)
	}
	if _, err := os.Stat(installed); !errors.Is(err, os.ErrNotExist) {
		t.Error("the installed agent is still there")
	}
	if _, err := os.Stat(binary); !errors.Is(err, os.ErrNotExist) {
		t.Error("the downloaded copy was not removed")
	}

	// Uninstalling again is not an error and runs nothing.
	before := len(e.calls())
	r = e.run(Uninstall(e.opts), struct{}{})
	if r.Status != protocol.StatusSucceeded || meshResult(t, r).Installed || len(e.calls()) != before {
		t.Errorf("second uninstall: %s %q, %d commands", r.Status, r.Message, len(e.calls())-before)
	}
}

func TestInstallWaitsForTheNodeID(t *testing.T) {
	// The agent has no identity for the first two queries.
	e := newEnv(t)
	_ = os.WriteFile(filepath.Join(e.root, "nodeid"), []byte(sampleNodeID), 0o600)
	_ = os.WriteFile(filepath.Join(e.root, "nodeid-after"), []byte("2"), 0o600)
	r := e.run(Install(e.opts), e.installSpec(fakeAgentScript(e.root, 0)))
	if res := meshResult(t, r); r.Status != protocol.StatusSucceeded || res.MeshNodeID != "node//"+sampleNodeID {
		t.Errorf("status = %s result = %+v", r.Status, res)
	}
	if n := len(e.calls()); n != 4 {
		t.Errorf("%d commands, want install + 3 node id queries", n)
	}
}

func TestInstallWithoutNodeID(t *testing.T) {
	// Installed, but the node id never becomes available: say so.
	e := newEnv(t)
	r := e.run(Install(e.opts), e.installSpec(fakeAgentScript(e.root, 0)))
	if r.Status != protocol.StatusSucceeded {
		t.Fatalf("status = %s (%s)", r.Status, r.Message)
	}
	if res := meshResult(t, r); !res.Installed || res.MeshNodeID != "" {
		t.Errorf("result = %+v", res)
	}
	if !strings.Contains(r.Message, "node id could not be determined") {
		t.Errorf("message = %q", r.Message)
	}
	raw, _ := json.Marshal(meshResult(t, r))
	if string(raw) != `{"installed":true}` {
		t.Errorf("result JSON = %s", raw)
	}

	// Garbage instead of a node id is not passed on.
	e = newEnv(t)
	_ = os.WriteFile(filepath.Join(e.root, "nodeid"), []byte("<script>alert(1)</script>\n"), 0o600)
	r = e.run(Install(e.opts), e.installSpec(fakeAgentScript(e.root, 0)))
	if res := meshResult(t, r); res.MeshNodeID != "" {
		t.Errorf("node id = %q", res.MeshNodeID)
	}
}

func TestInstallHashMismatchRunsNothing(t *testing.T) {
	e := newEnv(t)
	script := fakeAgentScript(e.root, 0)
	for name, mutate := range map[string]func(*protocol.MeshInstallSpec){
		"hash": func(s *protocol.MeshInstallSpec) { s.SHA256 = strings.Repeat("0", 64) },
		"size": func(s *protocol.MeshInstallSpec) { s.SizeBytes++ },
	} {
		spec := e.installSpec(script)
		mutate(&spec)
		r := e.run(Install(e.opts), spec)
		if r.Status != protocol.StatusRejected {
			t.Errorf("%s mismatch: status = %s (%s)", name, r.Status, r.Message)
		}
		if calls := e.calls(); len(calls) != 0 {
			t.Fatalf("%s mismatch: the binary was executed: %v", name, calls)
		}
		if entries, _ := os.ReadDir(e.opts.Dir); len(entries) != 0 {
			t.Errorf("%s mismatch: files left in the directory: %v", name, entries)
		}
	}
	// Invalid specs never reach the download.
	downloads := e.blobs.downloads
	spec := e.installSpec(script)
	spec.FileName = "../meshagent"
	if r := e.run(Install(e.opts), spec); r.Status != protocol.StatusRejected || e.blobs.downloads != downloads {
		t.Errorf("invalid spec: %s, downloads %d", r.Status, e.blobs.downloads-downloads)
	}
}

func TestInstallFailureIsReported(t *testing.T) {
	e := newEnv(t)
	r := e.run(Install(e.opts), e.installSpec(fakeAgentScript(e.root, 3)))
	if r.Status != protocol.StatusFailed || r.ExitCode == nil || *r.ExitCode != 3 {
		t.Fatalf("status = %s exit = %v (%s)", r.Status, r.ExitCode, r.Message)
	}
	if res := meshResult(t, r); res.Installed {
		t.Error("reported as installed")
	}
	// The half-finished install can be cleaned up with mesh.uninstall, which
	// falls back to the downloaded copy.
	r = e.run(Uninstall(e.opts), struct{}{})
	if r.Status != protocol.StatusSucceeded {
		t.Errorf("uninstall after a failed install: %s (%s)", r.Status, r.Message)
	}
	calls := e.calls()
	if last := calls[len(calls)-1]; last != filepath.Join(e.opts.Dir, "meshagent")+" -fulluninstall" {
		t.Errorf("uninstall command = %q", last)
	}
}

// recordingCommander proves that the commands go through the Commander
// interface when one is supplied.
type recordingCommander struct{ calls []string }

func (c *recordingCommander) Run(_ context.Context, path string, args []string, out io.Writer) (int, error) {
	c.calls = append(c.calls, filepath.Base(path)+" "+strings.Join(args, " "))
	if len(args) == 1 && args[0] == "-nodeid" {
		_, _ = io.WriteString(out, sampleNodeID+"\n")
	}
	return 0, nil
}

func TestCommanderInterface(t *testing.T) {
	e := newEnv(t)
	cmd := &recordingCommander{}
	e.opts.Commander = cmd
	// "Installed" binary present so that the node id is queried.
	_ = os.MkdirAll(filepath.Dir(e.opts.InstalledPaths[0]), 0o700)
	_ = os.WriteFile(e.opts.InstalledPaths[0], []byte("x"), 0o700)
	r := e.run(Install(e.opts), e.installSpec([]byte("any bytes")))
	if res := meshResult(t, r); r.Status != protocol.StatusSucceeded || res.MeshNodeID != "node//"+sampleNodeID {
		t.Fatalf("status = %s result = %+v", r.Status, res)
	}
	if got := strings.Join(cmd.calls, "; "); got != "meshagent -fullinstall; meshagent -nodeid" {
		t.Errorf("commands = %q", got)
	}
}

// fakeRestart writes a stand-in for "launchctl kickstart" / "systemctl
// restart" that records its call and exits with exitCode.
func fakeRestart(t *testing.T, root string, exitCode int) []string {
	t.Helper()
	path := filepath.Join(root, "restart")
	script := fmt.Sprintf("#!/bin/sh\necho \"restart $*\" >> %q\nexit %d\n", filepath.Join(root, "calls"), exitCode)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // G306: test stand-in must be executable
		t.Fatal(err)
	}
	return []string{path, "system/meshagent"}
}

func TestInstallWritesTheSettingsFile(t *testing.T) {
	// macOS / Linux: MeshCentral's binary has no settings. They are written
	// next to the binary before the install, and the installed copy, which
	// "-fullinstall" did not give a settings file, gets one followed by a
	// service restart; only then is the node id read.
	e := newEnv(t)
	e.opts.RestartCommand = fakeRestart(t, e.root, 0)
	_ = os.WriteFile(filepath.Join(e.root, "nodeid"), []byte(sampleNodeID+"\n"), 0o600)
	spec := e.installSpec(fakeAgentScript(e.root, 0))
	spec.MeshSettings = sampleSettings
	r := e.run(Install(e.opts), spec)
	if res := meshResult(t, r); r.Status != protocol.StatusSucceeded || res.MeshNodeID != "node//"+sampleNodeID {
		t.Fatalf("status = %s (%s) result = %+v", r.Status, r.Message, res)
	}
	if got, err := os.ReadFile(filepath.Join(e.root, "msh-at-install")); err != nil || string(got) != sampleSettings {
		t.Errorf("settings next to the binary during the install: %q, %v", got, err)
	}
	installed := filepath.Join(e.root, "installed", "meshagent.msh")
	got, err := os.ReadFile(installed)
	if err != nil || string(got) != sampleSettings {
		t.Fatalf("installed settings: %q, %v", got, err)
	}
	if fi, _ := os.Stat(installed); fi.Mode().Perm() != 0o644 {
		t.Errorf("installed settings mode = %v", fi.Mode().Perm())
	}
	calls := e.calls()
	if len(calls) != 3 || !strings.HasSuffix(calls[0], " -fullinstall") || calls[1] != "restart system/meshagent" || !strings.HasSuffix(calls[2], " -nodeid") {
		t.Errorf("commands run:\n%s", strings.Join(calls, "\n"))
	}
	if _, err := os.Stat(installed + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("temporary settings file left behind")
	}

	// Uninstall removes the downloaded copy of the settings too.
	if r := e.run(Uninstall(e.opts), struct{}{}); r.Status != protocol.StatusSucceeded {
		t.Fatalf("uninstall: %s (%s)", r.Status, r.Message)
	}
	if entries, _ := os.ReadDir(e.opts.Dir); len(entries) != 0 {
		t.Errorf("files left after uninstall: %v", entries)
	}
}

func TestInstallKeepsSettingsTheInstallerCopied(t *testing.T) {
	// When "-fullinstall" copies the settings itself, nothing is rewritten
	// and the service is not restarted.
	e := newEnv(t)
	e.opts.RestartCommand = fakeRestart(t, e.root, 0)
	_ = os.WriteFile(filepath.Join(e.root, "copy-msh"), nil, 0o600)
	_ = os.WriteFile(filepath.Join(e.root, "nodeid"), []byte(sampleNodeID+"\n"), 0o600)
	spec := e.installSpec(fakeAgentScript(e.root, 0))
	spec.MeshSettings = sampleSettings
	if r := e.run(Install(e.opts), spec); r.Status != protocol.StatusSucceeded {
		t.Fatalf("status = %s (%s)", r.Status, r.Message)
	}
	for _, c := range e.calls() {
		if strings.HasPrefix(c, "restart") {
			t.Errorf("service restarted although the settings were in place: %v", e.calls())
		}
	}
}

func TestInstallReportsAFailedRestart(t *testing.T) {
	e := newEnv(t)
	e.opts.RestartCommand = fakeRestart(t, e.root, 5)
	spec := e.installSpec(fakeAgentScript(e.root, 0))
	spec.MeshSettings = sampleSettings
	r := e.run(Install(e.opts), spec)
	if r.Status != protocol.StatusFailed || !strings.Contains(r.Message, "restart MeshAgent: exit code 5") {
		t.Fatalf("status = %s (%s)", r.Status, r.Message)
	}
	// Installed (so it can be removed with mesh.uninstall), but not usable.
	if res := meshResult(t, r); !res.Installed || res.MeshNodeID != "" {
		t.Errorf("result = %+v", res)
	}
}

func TestInstallWithoutSettingsDoesNotRestart(t *testing.T) {
	// Windows-style spec (settings inside the binary): unchanged behaviour.
	e := newEnv(t)
	e.opts.RestartCommand = fakeRestart(t, e.root, 0)
	if r := e.run(Install(e.opts), e.installSpec(fakeAgentScript(e.root, 0))); r.Status != protocol.StatusSucceeded {
		t.Fatalf("status = %s (%s)", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(e.root, "installed", "meshagent.msh")); !errors.Is(err, os.ErrNotExist) {
		t.Error("settings file written without settings")
	}
	for _, c := range e.calls() {
		if strings.HasPrefix(c, "restart") {
			t.Errorf("restarted: %v", e.calls())
		}
	}
}
