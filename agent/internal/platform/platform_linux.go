//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// OSFamily is the protocol name of the OS this binary was built for.
const OSFamily = "linux"

// lookupUser resolves an account by name. With CGO disabled os/user only
// reads /etc/passwd, so directory (LDAP/SSSD) accounts are resolved through
// getent when the plain lookup fails.
func lookupUser(ctx context.Context, name string) (*User, error) {
	if u, err := user.Lookup(name); err == nil {
		return &User{Name: u.Username, UID: u.Uid, GID: u.Gid, Home: u.HomeDir}, nil
	}
	return lookupUserFallback(ctx, name)
}

func lookupUserFallback(ctx context.Context, key string) (*User, error) {
	// The key comes from logind / utmp, but is still treated as untrusted:
	// only plain account names or numeric ids are passed on, after "--".
	if !validAccountKey(key) {
		return nil, fmt.Errorf("user %q not found", key)
	}
	getent, err := exec.LookPath("getent")
	if err != nil {
		return nil, fmt.Errorf("user %q not found", key)
	}
	out, err := output(ctx, 10*time.Second, getent, "passwd", "--", key)
	if err != nil {
		return nil, fmt.Errorf("user %q not found", key)
	}
	e, ok := ParsePasswdLine(out)
	if !ok {
		return nil, fmt.Errorf("user %q not found", key)
	}
	return &User{Name: e.Name, UID: e.UID, GID: e.GID, Home: e.Home, Shell: e.Shell}, nil
}

// sessions queries systemd-logind. ok is false when loginctl is unavailable
// (containers, non-systemd distributions).
func sessions(ctx context.Context) (list []LoginSession, ok bool) {
	loginctl, err := exec.LookPath("loginctl")
	if err != nil {
		return nil, false
	}
	out, err := output(ctx, 10*time.Second, loginctl, "list-sessions", "--no-legend")
	if err != nil {
		return nil, false
	}
	for _, id := range ParseLoginctlSessionIDs(out) {
		detail, err := output(ctx, 10*time.Second, loginctl, "show-session", id,
			"-p", "Name", "-p", "Active", "-p", "Remote", "-p", "Class", "-p", "Type", "-p", "Seat", "-p", "State")
		if err != nil {
			continue
		}
		list = append(list, ParseLoginctlSession(detail))
	}
	return list, true
}

func who(ctx context.Context) []string {
	path, err := exec.LookPath("who")
	if err != nil {
		return nil
	}
	out, err := output(ctx, 10*time.Second, path)
	if err != nil {
		return nil
	}
	return ParseWho(out)
}

func (n *native) ConsoleUser(ctx context.Context) (*User, error) {
	list, ok := sessions(ctx)
	if !ok {
		return nil, ErrNoConsoleUser
	}
	name := PickConsoleUser(list)
	if name == "" {
		return nil, ErrNoConsoleUser
	}
	u, err := lookupUser(ctx, name)
	if err != nil {
		return nil, err
	}
	if u.UID == "0" {
		return nil, ErrNoConsoleUser
	}
	return u, nil
}

func (n *native) LoggedInUsers(ctx context.Context) ([]string, error) {
	if list, ok := sessions(ctx); ok {
		return LoggedInFromSessions(list), nil
	}
	return who(ctx), nil
}

// userCommand builds the command for running as the console user:
// "runuser -u <user> -- <argv>" (PROTOCOL.md section 6.2). When runuser is
// not installed the process is started directly with the user's credentials.
func userCommand(c Command) (*exec.Cmd, error) {
	u := c.AsUser
	env := baseUserEnv(u)
	if u.UID != "" {
		runtimeDir := "/run/user/" + u.UID
		if fi, err := os.Stat(runtimeDir); err == nil && fi.IsDir() {
			env = append(env, "XDG_RUNTIME_DIR="+runtimeDir, "DBUS_SESSION_BUS_ADDRESS=unix:path="+runtimeDir+"/bus")
		}
	}
	env = MergeEnv(env, c.Env, false)

	if runuser, err := exec.LookPath("runuser"); err == nil {
		args := append([]string{"-u", u.Name, "--", c.Path}, c.Args...)
		cmd := exec.Command(runuser, args...)
		cmd.Env = env
		return cmd, nil
	}

	uid, err := strconv.ParseUint(u.UID, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid %q", u.UID)
	}
	gid, err := strconv.ParseUint(u.GID, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid gid %q", u.GID)
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	if lu, err := user.LookupId(u.UID); err == nil {
		if gids, err := lu.GroupIds(); err == nil {
			for _, g := range gids {
				if v, err := strconv.ParseUint(g, 10, 32); err == nil {
					cred.Groups = append(cred.Groups, uint32(v))
				}
			}
		}
	}
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	return cmd, nil
}

func (n *native) PendingReboot(ctx context.Context) (bool, error) {
	// Debian / Ubuntu.
	for _, p := range []string{"/var/run/reboot-required", "/run/reboot-required"} {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	// RHEL family: needs-restarting -r exits 1 when a reboot is required.
	path, err := exec.LookPath("needs-restarting")
	if err != nil {
		return false, nil
	}
	_, err = output(ctx, 60*time.Second, path, "-r")
	if err == nil {
		return false, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return true, nil
	}
	return false, fmt.Errorf("needs-restarting: %w", err)
}

func (n *native) MachineID(_ context.Context) (string, error) {
	// machine-id first; the firmware UUID is the fallback for images whose
	// machine-id was never initialised (it is readable by root only).
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if id := ParseMachineID(string(data)); id != "" {
			return id, nil
		}
	}
	return "", errors.New("machine id not available")
}
