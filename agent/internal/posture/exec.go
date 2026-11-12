package posture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Command limits.
const (
	// DefaultCmdTimeout bounds a helper command without its own timeout.
	DefaultCmdTimeout = 30 * time.Second
	// PowerShellTimeout bounds one PowerShell invocation (start-up alone can
	// take several seconds on a busy machine).
	PowerShellTimeout = 90 * time.Second
	// DefaultMaxStdout and MaxStderr bound the captured output.
	DefaultMaxStdout = 4 << 20
	MaxStderr        = 64 << 10
)

// Cmd is a fixed helper command. Arguments are an argv array; nothing is
// interpreted by a shell. Values that come from the server are never placed
// in a script text: they travel as arguments or in Env.
type Cmd struct {
	Path string
	Args []string
	// Env holds extra KEY=VALUE variables.
	Env []string
	// Stdin is fed to the process ("" leaves stdin empty).
	Stdin string
	// Timeout bounds the run (default DefaultCmdTimeout).
	Timeout time.Duration
	// MaxStdout bounds the captured stdout (default DefaultMaxStdout).
	MaxStdout int
	// AsUser runs the command in that user's session (nil: as the agent).
	AsUser *platform.User
}

// CmdResult is the captured output of a finished command.
type CmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Combined returns stdout followed by stderr.
func (r CmdResult) Combined() string {
	if r.Stderr == "" {
		return r.Stdout
	}
	if r.Stdout == "" {
		return r.Stderr
	}
	return r.Stdout + "\n" + r.Stderr
}

// Exec runs helper commands through the Platform (process-tree kill on
// timeout, run-as-user support) with bounded output.
type Exec struct{ Platform platform.Platform }

// Run executes c and waits for it. A non-zero exit code is not an error; the
// error is non-nil only when the process could not run to completion.
func (e Exec) Run(ctx context.Context, c Cmd) (CmdResult, error) {
	if c.Path == "" {
		return CmdResult{ExitCode: platform.ExitCodeUnknown}, errors.New("command not available")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultCmdTimeout
	}
	maxOut := c.MaxStdout
	if maxOut <= 0 {
		maxOut = DefaultMaxStdout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout := &capBuffer{limit: maxOut}
	stderr := &capBuffer{limit: MaxStderr}
	pc := platform.Command{
		Path:   c.Path,
		Args:   c.Args,
		Env:    c.Env,
		Stdout: stdout,
		Stderr: stderr,
		AsUser: c.AsUser,
	}
	if c.Stdin != "" {
		pc.Stdin = strings.NewReader(c.Stdin)
	}
	code, err := e.Platform.Run(cctx, pc)
	res := CmdResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}
	if err != nil {
		return res, fmt.Errorf("%s: %w", filepath.Base(c.Path), err)
	}
	return res, nil
}

// Output runs c and returns its stdout; a non-zero exit code is an error
// that carries the tail of stderr.
func (e Exec) Output(ctx context.Context, c Cmd) (string, error) {
	res, err := e.Run(ctx, c)
	if err != nil {
		return res.Stdout, err
	}
	if res.ExitCode != 0 {
		return res.Stdout, fmt.Errorf("%s: exit code %d%s", filepath.Base(c.Path), res.ExitCode, errTail(res.Stderr))
	}
	return res.Stdout, nil
}

func errTail(stderr string) string {
	s := OneLine(stderr, 200)
	if s == "" {
		return ""
	}
	return ": " + s
}

// OneLine collapses s to a single line of at most limit bytes (valid UTF-8,
// no control characters).
func OneLine(s string, limit int) string {
	s = strings.Join(strings.Fields(strings.ToValidUTF8(s, "?")), " ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > limit {
		cut := limit
		for cut > 0 && !isRuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// capBuffer keeps the first limit bytes written to it and discards the rest.
type capBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *capBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *capBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// toolDirs are the only directories helper tools are looked up in. $PATH is
// deliberately not used: a service's PATH is often minimal, and a fixed list
// cannot be redirected to another binary through the environment.
var toolDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// LookTool returns the absolute path of the first of names that exists as a
// regular file in the fixed system directories, or "".
func LookTool(names ...string) string {
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, `/\`) {
			continue
		}
		for _, dir := range toolDirs {
			p := filepath.Join(dir, name)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				return p
			}
		}
	}
	return ""
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readLimited reads at most limit bytes of a file.
func readLimited(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, int64(limit)))
}

// PowerShellPath is Windows PowerShell 5.1, which ships with every supported
// Windows version.
func PowerShellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
}

// PowerShell builds the invocation of a fixed PowerShell script: the script
// text goes to stdin ("-Command -") and prints one JSON document. env carries
// any value that is not a constant; such values are read inside the script
// from $env: and are never interpolated into the script text.
//
// "-ExecutionPolicy Bypass" applies to this one process only (it is not a
// system setting): the built-in NetSecurity, Defender and BitLocker modules
// are script modules, which a "Restricted" policy would refuse to load.
func PowerShell(script string, env ...string) Cmd {
	return Cmd{
		Path:    PowerShellPath(),
		Args:    []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"},
		Stdin:   script,
		Env:     env,
		Timeout: PowerShellTimeout,
	}
}
