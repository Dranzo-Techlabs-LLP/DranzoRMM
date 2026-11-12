//go:build windows

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// OSFamily is the protocol name of the OS this binary was built for.
const OSFamily = "windows"

const (
	noSession = 0xFFFFFFFF
	waitDelay = 3 * time.Second
)

type native struct{}

func newNative() Platform { return &native{} }

// userForSession resolves the user of an interactive session through its
// primary token. WTSQueryUserToken requires the agent to run as LocalSystem.
func userForSession(sessionID uint32) (*User, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		if errors.Is(err, windows.ERROR_NO_TOKEN) {
			return nil, ErrNoConsoleUser
		}
		return nil, fmt.Errorf("query session user token: %w", err)
	}
	defer func() { _ = token.Close() }()
	tu, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read token user: %w", err)
	}
	sid := tu.User.Sid
	name := sid.String()
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		name = account
		if domain != "" {
			name = domain + `\` + account
		}
	}
	return &User{Name: name, SID: sid.String(), SessionID: sessionID}, nil
}

type sessionInfo struct {
	id     uint32
	active bool
}

func enumerateSessions() ([]sessionInfo, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return nil, fmt.Errorf("enumerate sessions: %w", err)
	}
	// The Win32 API returns a C array that must be read and freed through unsafe.
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info))) //nolint:gosec // G103: Win32 interop
	out := make([]sessionInfo, 0, count)
	for _, s := range unsafe.Slice(info, count) { //nolint:gosec // G103: Win32 interop, count comes from the same call
		out = append(out, sessionInfo{id: s.SessionID, active: s.State == windows.WTSActive})
	}
	return out, nil
}

// ConsoleUser returns the user of the active console session, falling back to
// the first active (e.g. Remote Desktop) session.
func (n *native) ConsoleUser(_ context.Context) (*User, error) {
	if id := windows.WTSGetActiveConsoleSessionId(); id != noSession {
		if u, err := userForSession(id); err == nil {
			return u, nil
		} else if !errors.Is(err, ErrNoConsoleUser) {
			return nil, err
		}
	}
	list, err := enumerateSessions()
	if err != nil {
		return nil, err
	}
	for _, s := range list {
		if !s.active {
			continue
		}
		if u, err := userForSession(s.id); err == nil {
			return u, nil
		}
	}
	return nil, ErrNoConsoleUser
}

func (n *native) LoggedInUsers(_ context.Context) ([]string, error) {
	list, err := enumerateSessions()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var users []string
	for _, s := range list {
		u, err := userForSession(s.id)
		if err != nil {
			continue
		}
		if _, dup := seen[u.Name]; dup {
			continue
		}
		seen[u.Name] = struct{}{}
		users = append(users, u.Name)
	}
	return users, nil
}

// envBlockToStrings converts a Win32 environment block (consecutive
// NUL-terminated UTF-16 strings, ended by an empty string) to KEY=VALUE strings.
func envBlockToStrings(block *uint16) []string {
	var out []string
	p := unsafe.Pointer(block) //nolint:gosec // G103: Win32 interop, block comes from CreateEnvironmentBlock
	for len(out) < 4096 {
		s := windows.UTF16PtrToString((*uint16)(p))
		if s == "" {
			break
		}
		out = append(out, s)
		p = unsafe.Add(p, (len(utf16.Encode([]rune(s)))+1)*2)
	}
	return out
}

func (n *native) Run(ctx context.Context, c Command) (int, error) {
	if c.Path == "" {
		return ExitCodeUnknown, errors.New("empty command")
	}
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Dir = c.Dir
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	cmd.WaitDelay = waitDelay
	// CREATE_NO_WINDOW: a background job does not pop up a console window.
	// The process itself stays visible in the process list like any other.
	attr := &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP}

	if c.AsUser == nil {
		cmd.Env = MergeEnv(os.Environ(), c.Env, true)
	} else {
		// Run in the user's interactive session with the user's own token
		// (os/exec calls CreateProcessAsUser when SysProcAttr.Token is set)
		// and the user's own environment block.
		var token windows.Token
		if err := windows.WTSQueryUserToken(c.AsUser.SessionID, &token); err != nil {
			if errors.Is(err, windows.ERROR_NO_TOKEN) {
				return ExitCodeUnknown, ErrNoConsoleUser
			}
			return ExitCodeUnknown, fmt.Errorf("query session user token: %w", err)
		}
		defer func() { _ = token.Close() }()
		var block *uint16
		if err := windows.CreateEnvironmentBlock(&block, token, false); err != nil {
			return ExitCodeUnknown, fmt.Errorf("create user environment: %w", err)
		}
		userEnv := envBlockToStrings(block)
		_ = windows.DestroyEnvironmentBlock(block)
		cmd.Env = MergeEnv(userEnv, c.Env, true)
		attr.Token = syscall.Token(token)
	}
	cmd.SysProcAttr = attr

	// A job object groups the process tree so that it can be terminated as a whole.
	job, jobErr := windows.CreateJobObject(nil, nil)
	if jobErr == nil {
		defer func() { _ = windows.CloseHandle(job) }()
	}
	if err := cmd.Start(); err != nil {
		return ExitCodeUnknown, fmt.Errorf("start %s: %w", c.Path, err)
	}
	inJob := false
	if jobErr == nil {
		if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil { //nolint:gosec // pid is non-negative
			inJob = windows.AssignProcessToJobObject(job, h) == nil
			_ = windows.CloseHandle(h)
		}
	}
	var err error
	done := make(chan struct{})
	go func() {
		err = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if inJob {
			_ = windows.TerminateJobObject(job, 1)
		} else {
			// Fallback: taskkill terminates the process and its descendants.
			kill := exec.Command("taskkill.exe", "/T", "/F", "/PID", fmt.Sprint(cmd.Process.Pid))
			_ = kill.Run()
			_ = cmd.Process.Kill()
		}
		<-done
		return ExitCodeUnknown, ctx.Err()
	}
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return ExitCodeUnknown, err
		}
	}
	if cmd.ProcessState == nil {
		return ExitCodeUnknown, errors.New("process state unavailable")
	}
	return cmd.ProcessState.ExitCode(), nil
}

// GrantUser replaces the ACL of path with: SYSTEM and Administrators full
// control, the user read + execute (+ write for directories so the user can
// create temp files next to a script), inheritance from the parent disabled.
func (n *native) GrantUser(path string, u *User) error {
	if u == nil || u.SID == "" {
		return errors.New("no user SID")
	}
	if _, err := windows.StringToSid(u.SID); err != nil {
		return fmt.Errorf("invalid SID: %w", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sddl := "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + u.SID + ")"
	if fi.IsDir() {
		sddl = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + u.SID + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// PendingReboot checks the well-known registry indicators: Component Based
// Servicing, Windows Update and pending file rename operations.
func (n *native) PendingReboot(_ context.Context) (bool, error) {
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) ||
		keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		return true, nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false, nil
	}
	defer func() { _ = k.Close() }()
	vals, _, err := k.GetStringsValue("PendingFileRenameOperations")
	if err != nil {
		return false, nil
	}
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true, nil
		}
	}
	return false, nil
}

func (n *native) MachineID(_ context.Context) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open Cryptography key: %w", err)
	}
	defer func() { _ = k.Close() }()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("read MachineGuid: %w", err)
	}
	return ParseMachineID(guid), nil
}
