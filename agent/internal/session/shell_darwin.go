//go:build darwin

package session

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

const defaultLang = "en_US.UTF-8"

// planShell decides how the shell is started.
//
// System: the agent's own identity (root), a login shell with a clean
// environment.
//
// User: the logged-in console user, with the same mechanics as script jobs
// (platform.Run):
//
//	launchctl asuser <uid> sudo -n -H -u #<uid> --preserve-env=<names> -- <shell> -l
//
// launchctl asuser enters the user's bootstrap (GUI) namespace and sudo
// drops root to the user with the user's full group list.
func planShell(ctx context.Context, spec TerminalSpec) (*shellPlan, error) {
	if spec.AsUser == nil {
		return systemPlan(), nil
	}
	u := spec.AsUser
	uid, gid, ok := userIDs(u)
	if !ok || uid == 0 {
		return nil, errors.New("the logged-in user has no usable user id")
	}
	shell := userShell(ctx, u)
	env := userEnv(u, shell)
	plan := &shellPlan{path: shell, args: []string{"-l"}, env: env, dir: dirOrRoot(u.Home), ttyUID: uid, ttyGID: gid}

	switch euid := os.Geteuid(); {
	case euid == uid:
		// Development: the agent already runs as that user.
		plan.ttyUID, plan.ttyGID = -1, -1
		return plan, nil
	case euid != 0:
		return nil, errNotRoot
	}
	names := make([]string, 0, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok {
			names = append(names, k)
		}
	}
	plan.args = append([]string{"asuser", u.UID, "/usr/bin/sudo", "-n", "-H", "-u", "#" + u.UID,
		"--preserve-env=" + strings.Join(names, ","), "--", plan.path}, plan.args...)
	plan.path = "/bin/launchctl"
	return plan, nil
}

// userShell returns the user's login shell from the directory service, or
// the macOS default.
func userShell(ctx context.Context, u *platform.User) string {
	shell := u.Shell
	if shell == "" && u.Name != "" && !strings.ContainsAny(u.Name, "/\x00\n") {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := exec.CommandContext(cctx, "/usr/bin/dscl", ".", "-read", "/Users/"+u.Name, "UserShell").Output()
		cancel()
		if err == nil {
			shell = parseDsclShell(string(out))
		}
	}
	if allowedShell(shell) {
		return shell
	}
	if isExecutable("/bin/zsh") {
		return "/bin/zsh"
	}
	return systemShell()
}

// parseDsclShell parses "UserShell: /bin/zsh".
func parseDsclShell(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "UserShell:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
