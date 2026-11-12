//go:build linux

package session

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

const defaultLang = "C.UTF-8"

// lookRunuser finds runuser(1); tests replace it to exercise the fallback.
var lookRunuser = func() (string, error) { return exec.LookPath("runuser") }

// planShell decides how the shell is started.
//
// System: the agent's own identity (root), a login shell with a clean
// environment.
//
// User: the logged-in console user, with the same mechanics as script jobs
// (platform.Run): "runuser -u <user> -- <shell> -l", which sets up groups
// through the system's name service and opens a PAM session. Without
// runuser the shell is started directly with the user's credentials.
func planShell(ctx context.Context, spec TerminalSpec) (*shellPlan, error) {
	if spec.AsUser == nil {
		return systemPlan(), nil
	}
	u := spec.AsUser
	uid, gid, ok := userIDs(u)
	if !ok || uid == 0 {
		return nil, errors.New("the logged-in user has no usable user id")
	}
	if u.Name == "" || strings.HasPrefix(u.Name, "-") || strings.ContainsAny(u.Name, " \t\n\x00") {
		return nil, errors.New("the logged-in user has no usable account name")
	}
	shell := userShell(ctx, u)
	env := userEnv(u, shell)
	runtimeDir := "/run/user/" + u.UID
	if fi, err := os.Stat(runtimeDir); err == nil && fi.IsDir() {
		env = append(env, "XDG_RUNTIME_DIR="+runtimeDir, "DBUS_SESSION_BUS_ADDRESS=unix:path="+runtimeDir+"/bus")
	}
	plan := &shellPlan{path: shell, args: []string{"-l"}, env: env, dir: dirOrRoot(u.Home), ttyUID: uid, ttyGID: gid}

	switch euid := os.Geteuid(); {
	case euid == uid:
		// Development: the agent already runs as that user.
		plan.ttyUID, plan.ttyGID = -1, -1
		return plan, nil
	case euid != 0:
		return nil, errNotRoot
	}
	if runuser, err := lookRunuser(); err == nil {
		plan.args = append([]string{"-u", u.Name, "--", plan.path}, plan.args...)
		plan.path = runuser
		// runuser changes identity itself; the working directory is entered
		// as root, which may not be possible for a home on a root-squashed
		// network file system: the shell then starts in "/".
		return plan, nil
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)} //nolint:gosec // G115: parsed with a 31 bit limit
	cred.Groups = supplementaryGroups(ctx, u)
	plan.cred = cred
	return plan, nil
}

// userShell returns the user's login shell, or the system shell when the
// account has none that may be used.
func userShell(ctx context.Context, u *platform.User) string {
	shell := u.Shell
	if shell == "" {
		shell = passwdShell(ctx, u.Name)
	}
	if allowedShell(shell) {
		return shell
	}
	return systemShell()
}

// passwdShell looks the shell up in /etc/passwd and, for directory accounts,
// through getent.
func passwdShell(ctx context.Context, name string) string {
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if e, ok := platform.ParsePasswdLine(line); ok && e.Name == name {
				return e.Shell
			}
		}
	}
	getent, err := exec.LookPath("getent")
	if err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, getent, "passwd", "--", name).Output()
	if err != nil {
		return ""
	}
	if e, ok := platform.ParsePasswdLine(string(out)); ok && e.Name == name {
		return e.Shell
	}
	return ""
}

// supplementaryGroups resolves the user's groups: "id -G" first (it asks the
// system's name service, so directory groups are included), then /etc/group.
func supplementaryGroups(ctx context.Context, u *platform.User) []uint32 {
	var groups []uint32
	add := func(fields []string) {
		for _, f := range fields {
			if v, err := strconv.ParseUint(f, 10, 32); err == nil {
				groups = append(groups, uint32(v))
			}
		}
	}
	if id, err := exec.LookPath("id"); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := exec.CommandContext(cctx, id, "-G", "--", u.Name).Output()
		cancel()
		if err == nil {
			add(strings.Fields(string(out)))
			if len(groups) > 0 {
				return groups
			}
		}
	}
	if lu, err := user.LookupId(u.UID); err == nil {
		if gids, err := lu.GroupIds(); err == nil {
			add(gids)
		}
	}
	return groups
}
