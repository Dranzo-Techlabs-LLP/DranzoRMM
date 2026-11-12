//go:build darwin

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// OSFamily is the protocol name of the OS this binary was built for.
const OSFamily = "macos"

// lookupUserID resolves an account by numeric id. On macOS os/user queries
// Open Directory through libSystem even in a CGO-free build.
func lookupUserID(uid string) (*User, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return nil, fmt.Errorf("user id %s not found: %w", uid, err)
	}
	return &User{Name: u.Username, UID: u.Uid, GID: u.Gid, Home: u.HomeDir}, nil
}

// envNames returns the variable names of a KEY=VALUE list.
func envNames(env []string) []string {
	names := make([]string, 0, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" {
			names = append(names, k)
		}
	}
	return names
}

// ConsoleUser returns the owner of /dev/console, which macOS assigns to the
// user of the active GUI session (root when nobody is logged in).
func (n *native) ConsoleUser(_ context.Context) (*User, error) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return nil, fmt.Errorf("stat /dev/console: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("console owner unavailable")
	}
	if st.Uid == 0 {
		return nil, ErrNoConsoleUser
	}
	u, err := lookupUserID(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		return nil, err
	}
	if u.Name == "root" || strings.HasPrefix(u.Name, "_") || u.Name == "loginwindow" {
		return nil, ErrNoConsoleUser
	}
	return u, nil
}

func (n *native) LoggedInUsers(ctx context.Context) ([]string, error) {
	out, err := output(ctx, 10*time.Second, "/usr/bin/who")
	if err != nil {
		return nil, err
	}
	return ParseWho(out), nil
}

// userCommand builds the command for running in the console user's session:
//
//	launchctl asuser <uid> sudo -n -H -u #<uid> --preserve-env=<names> -- <argv>
//
// launchctl asuser enters the user's bootstrap (GUI) namespace; sudo drops
// root to the user. Variables are handed over through the environment (kept
// by --preserve-env), never on the command line.
func userCommand(c Command) (*exec.Cmd, error) {
	u := c.AsUser
	if _, err := strconv.ParseUint(u.UID, 10, 32); err != nil {
		return nil, fmt.Errorf("invalid uid %q", u.UID)
	}
	env := MergeEnv(baseUserEnv(u), c.Env, false)
	args := []string{"asuser", u.UID, "/usr/bin/sudo", "-n", "-H", "-u", "#" + u.UID}
	if names := envNames(env); len(names) > 0 {
		args = append(args, "--preserve-env="+strings.Join(names, ","))
	}
	args = append(args, "--", c.Path)
	args = append(args, c.Args...)
	cmd := exec.Command("/bin/launchctl", args...)
	cmd.Env = env
	return cmd, nil
}

// PendingReboot: macOS has no reliable pending-reboot indicator.
func (n *native) PendingReboot(_ context.Context) (bool, error) { return false, nil }

func (n *native) MachineID(ctx context.Context) (string, error) {
	out, err := output(ctx, 10*time.Second, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", fmt.Errorf("ioreg: %w", err)
	}
	id := ParseIoregValue(out, "IOPlatformUUID")
	if id == "" {
		return "", errors.New("machine id not available")
	}
	return strings.ToLower(id), nil
}
