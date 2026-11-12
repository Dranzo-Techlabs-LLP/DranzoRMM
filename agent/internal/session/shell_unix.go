//go:build !windows

package session

import (
	"bufio"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

const (
	termType    = "xterm-256color"
	defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// systemShell is the shell of a terminal that runs as the agent itself.
func systemShell() string {
	for _, sh := range []string{"/bin/bash", "/usr/bin/bash", "/bin/sh"} {
		if isExecutable(sh) {
			return sh
		}
	}
	return "/bin/sh"
}

// allowedShell reports whether shell is a real login shell: an absolute path
// to an executable that /etc/shells lists (when that file exists). Accounts
// with nologin / false as shell get the system shell instead.
func allowedShell(shell string) bool {
	if !strings.HasPrefix(shell, "/") || !isExecutable(shell) {
		return false
	}
	f, err := os.Open("/etc/shells")
	if err != nil {
		return !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false")
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == shell {
			return true
		}
	}
	return false
}

// langEnv keeps the agent's locale, defaulting to UTF-8.
func langEnv() string {
	if v := os.Getenv("LANG"); v != "" && !strings.ContainsAny(v, "\x00\n") {
		return v
	}
	return defaultLang
}

// systemEnv is the environment of a system terminal: a small, clean set
// rather than the service's own environment.
func systemEnv(shell string) (env []string, home string) {
	name, home := "root", "/"
	if cur, err := user.Current(); err == nil {
		name = cur.Username
		if cur.HomeDir != "" {
			home = cur.HomeDir
		}
	}
	path := os.Getenv("PATH")
	if path == "" || os.Geteuid() == 0 {
		path = defaultPath
	}
	return []string{
		"TERM=" + termType,
		"HOME=" + home,
		"USER=" + name,
		"LOGNAME=" + name,
		"SHELL=" + shell,
		"PATH=" + path,
		"LANG=" + langEnv(),
	}, home
}

// userEnv is the environment of a terminal that runs as u.
func userEnv(u *platform.User, shell string) []string {
	env := []string{
		"TERM=" + termType,
		"USER=" + u.Name,
		"LOGNAME=" + u.Name,
		"SHELL=" + shell,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"LANG=" + langEnv(),
	}
	if u.Home != "" {
		env = append(env, "HOME="+u.Home)
	}
	return env
}

func dirOrRoot(dir string) string {
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir
	}
	return "/"
}

// userIDs parses the numeric ids of u.
func userIDs(u *platform.User) (uid, gid int, ok bool) {
	uid64, err1 := strconv.ParseUint(u.UID, 10, 31)
	gid64, err2 := strconv.ParseUint(u.GID, 10, 31)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return int(uid64), int(gid64), true
}

// systemPlan is the shell of a terminal that runs as the agent itself.
func systemPlan() *shellPlan {
	shell := systemShell()
	env, home := systemEnv(shell)
	return &shellPlan{path: shell, args: []string{"-l"}, env: env, dir: dirOrRoot(home), ttyUID: -1, ttyGID: -1}
}
