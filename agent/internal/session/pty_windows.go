//go:build windows

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows terminal is a pseudo-console (ConPTY, Windows 10 1809+ /
// Server 2019+) created with the Win32 API from golang.org/x/sys/windows.
//
// NOTE: this file is compiled and vetted on every build but has not been
// executed yet (no Windows machine was available when it was written).

const jobObjectExtendedLimitInformation = 9

type winTerminal struct {
	in      *os.File // our end of the console's input pipe
	out     *os.File // our end of the console's output pipe
	process windows.Handle
	job     windows.Handle
	pid     int
	done    chan struct{}

	mu       sync.Mutex
	console  windows.Handle
	consOpen bool

	killOnce  sync.Once
	closeOnce sync.Once
}

func systemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// windowsShell is Windows PowerShell, or cmd.exe when it is missing.
func windowsShell() string {
	ps := filepath.Join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(ps); err == nil {
		return ps
	}
	return filepath.Join(systemRoot(), "System32", "cmd.exe")
}

// envBlock builds a Win32 environment block: NUL-terminated UTF-16 strings
// followed by an empty string.
func envBlock(env []string) []uint16 {
	var block []uint16
	for _, kv := range env {
		if kv == "" || strings.ContainsRune(kv, 0) {
			continue
		}
		block = append(block, utf16.Encode([]rune(kv))...)
		block = append(block, 0)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0)
}

// systemEnvironment is the service's environment without the agent's own
// variables (DRANZO_*), which a shell has no business seeing.
func systemEnvironment() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(strings.ToUpper(kv), "DRANZO_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// userProfileDir reads USERPROFILE from a Win32 environment block.
func userProfileDir(block *uint16) string {
	p := unsafe.Pointer(block) //nolint:gosec // G103: Win32 interop, block comes from CreateEnvironmentBlock
	for i := 0; i < 4096; i++ {
		s := windows.UTF16PtrToString((*uint16)(p))
		if s == "" {
			break
		}
		if k, v, ok := strings.Cut(s, "="); ok && strings.EqualFold(k, "USERPROFILE") {
			return v
		}
		p = unsafe.Add(p, (len(utf16.Encode([]rune(s)))+1)*2)
	}
	return ""
}

// startTerminal starts PowerShell (or cmd.exe) on a new pseudo-console.
//
// System: as the agent itself (LocalSystem). User: with the primary token of
// the logged-in user's session (WTSQueryUserToken + CreateProcessAsUser, the
// same mechanics as script jobs) and that user's own environment.
func startTerminal(_ context.Context, spec TerminalSpec) (Terminal, error) {
	if err := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find(); err != nil {
		return nil, &unsupportedError{what: "terminal sessions need Windows 10 version 1809 / Windows Server 2019 or later"}
	}

	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("create console input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		return nil, fmt.Errorf("create console output pipe: %w", err)
	}
	closeAll := func(handles ...windows.Handle) {
		for _, h := range handles {
			if h != 0 {
				_ = windows.CloseHandle(h)
			}
		}
	}

	var console windows.Handle
	size := windows.Coord{X: int16(spec.Cols), Y: int16(spec.Rows)} //nolint:gosec // G115: validated to 1..1000
	if err := windows.CreatePseudoConsole(size, inRead, outWrite, 0, &console); err != nil {
		closeAll(inRead, inWrite, outRead, outWrite)
		return nil, fmt.Errorf("create pseudo-console: %w", err)
	}
	// The pseudo-console holds its own duplicates of the console-side ends.
	closeAll(inRead, outWrite)
	fail := func(err error) (Terminal, error) {
		windows.ClosePseudoConsole(console)
		closeAll(inWrite, outRead)
		return nil, err
	}

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return fail(fmt.Errorf("allocate process attributes: %w", err))
	}
	defer attrs.Delete()
	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE takes the HPCON itself as the
	// value (not a pointer to it); reinterpret the handle's bits as a pointer.
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		*(*unsafe.Pointer)(unsafe.Pointer(&console)), unsafe.Sizeof(console)); err != nil { //nolint:gosec // G103: Win32 interop
		return fail(fmt.Errorf("attach pseudo-console: %w", err))
	}

	shell := windowsShell()
	appName, err := windows.UTF16PtrFromString(shell)
	if err != nil {
		return fail(err)
	}
	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{shell}))
	if err != nil {
		return fail(err)
	}

	si := new(windows.StartupInfoEx)
	si.Cb = uint32(unsafe.Sizeof(*si))
	// With STARTF_USESTDHANDLES and no handles the child takes its standard
	// handles from the pseudo-console instead of inheriting the service's.
	si.Flags = windows.STARTF_USESTDHANDLES
	si.ProcThreadAttributeList = attrs.List()

	// Suspended until the process is inside the job object, so that nothing
	// it starts can escape the job.
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_SUSPENDED)
	var pi windows.ProcessInformation

	if spec.AsUser == nil {
		block := envBlock(systemEnvironment())
		dir, derr := windows.UTF16PtrFromString(systemRoot())
		if derr != nil {
			return fail(derr)
		}
		err = windows.CreateProcess(appName, cmdLine, nil, nil, false, flags, &block[0], dir, &si.StartupInfo, &pi)
	} else {
		var token windows.Token
		if terr := windows.WTSQueryUserToken(spec.AsUser.SessionID, &token); terr != nil {
			if errors.Is(terr, windows.ERROR_NO_TOKEN) {
				return fail(errors.New("no logged-in user"))
			}
			return fail(fmt.Errorf("query session user token: %w", terr))
		}
		defer func() { _ = token.Close() }()
		var block *uint16
		if eerr := windows.CreateEnvironmentBlock(&block, token, false); eerr != nil {
			return fail(fmt.Errorf("create user environment: %w", eerr))
		}
		defer func() { _ = windows.DestroyEnvironmentBlock(block) }()
		var dir *uint16
		if profile := userProfileDir(block); profile != "" {
			if d, derr := windows.UTF16PtrFromString(profile); derr == nil {
				dir = d
			}
		}
		desktop, derr := windows.UTF16PtrFromString(`winsta0\default`)
		if derr != nil {
			return fail(derr)
		}
		si.Desktop = desktop
		err = windows.CreateProcessAsUser(token, appName, cmdLine, nil, nil, false, flags, block, dir, &si.StartupInfo, &pi)
	}
	if err != nil {
		return fail(fmt.Errorf("start shell: %w", err))
	}

	// A job object groups the shell and everything it starts, so the whole
	// tree can be terminated; closing the job handle kills it too.
	job, jerr := windows.CreateJobObject(nil, nil)
	if jerr == nil {
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		_, jerr = windows.SetInformationJobObject(job, jobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))) //nolint:gosec // G103: Win32 interop
		if jerr == nil {
			jerr = windows.AssignProcessToJobObject(job, pi.Process)
		}
		if jerr != nil {
			_ = windows.CloseHandle(job)
			job = 0
		}
	} else {
		job = 0
	}
	if job == 0 {
		// Without a job the process tree could outlive the session: do not
		// start the shell at all.
		_ = windows.TerminateProcess(pi.Process, 1)
		closeAll(pi.Thread, pi.Process)
		return fail(fmt.Errorf("put the shell into a job object: %w", jerr))
	}
	if _, rerr := windows.ResumeThread(pi.Thread); rerr != nil {
		_ = windows.TerminateJobObject(job, 1)
		closeAll(pi.Thread, pi.Process, job)
		return fail(fmt.Errorf("resume shell: %w", rerr))
	}
	_ = windows.CloseHandle(pi.Thread)

	t := &winTerminal{
		in:       os.NewFile(uintptr(inWrite), "conpty-input"),
		out:      os.NewFile(uintptr(outRead), "conpty-output"),
		process:  pi.Process,
		job:      job,
		pid:      int(pi.ProcessId),
		done:     make(chan struct{}),
		console:  console,
		consOpen: true,
	}
	go func() {
		_, _ = windows.WaitForSingleObject(t.process, windows.INFINITE)
		close(t.done)
	}()
	return t, nil
}

func (t *winTerminal) Read(p []byte) (int, error)  { return t.out.Read(p) }
func (t *winTerminal) Write(p []byte) (int, error) { return t.in.Write(p) }
func (t *winTerminal) Done() <-chan struct{}       { return t.done }
func (t *winTerminal) PID() int                    { return t.pid }

func (t *winTerminal) Resize(cols, rows int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.consOpen {
		return errors.New("terminal is closed")
	}
	return windows.ResizePseudoConsole(t.console, windows.Coord{X: int16(cols), Y: int16(rows)}) //nolint:gosec // G115: validated to 1..1000
}

// closeConsole closes the pseudo-console, which ends the output stream (the
// reader sees end-of-file once the remaining output was read).
func (t *winTerminal) closeConsole() {
	t.mu.Lock()
	open := t.consOpen
	t.consOpen = false
	console := t.console
	t.mu.Unlock()
	if open {
		// On older Windows versions this waits until the output pipe has
		// been drained, which the session's reader goroutine does.
		go windows.ClosePseudoConsole(console)
	}
}

// Kill terminates the shell and every process started from it.
func (t *winTerminal) Kill() {
	t.killOnce.Do(func() {
		_ = windows.TerminateJobObject(t.job, 1)
		_ = windows.TerminateProcess(t.process, 1)
		t.closeConsole()
	})
}

func (t *winTerminal) Close() error {
	t.closeOnce.Do(func() {
		t.closeConsole()
		_ = t.in.Close()
		_ = t.out.Close()
		// Closing the job handle kills anything still in it.
		_ = windows.CloseHandle(t.job)
		go func() {
			<-t.done
			_ = windows.CloseHandle(t.process)
		}()
	})
	return nil
}
