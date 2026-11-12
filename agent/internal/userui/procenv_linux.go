//go:build linux

package userui

import (
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// graphicalProcEnv returns the environment of one of the user's processes
// that has a display (DISPLAY or WAYLAND_DISPLAY), read from /proc as root.
// It is how the Xauthority file and the session bus of the user's desktop are
// found. The values are only ever handed back to a helper running as that
// same user.
func graphicalProcEnv(uid string) map[string]string {
	want, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		return nil
	}
	dir, err := os.Open("/proc")
	if err != nil {
		return nil
	}
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil
	}
	var fallback map[string]string
	checked := 0
	for _, name := range names {
		if _, err := strconv.ParseUint(name, 10, 32); err != nil {
			continue
		}
		fi, err := os.Stat("/proc/" + name)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || uint64(st.Uid) != want {
			continue
		}
		if checked++; checked > 2048 {
			break
		}
		env := readProcEnv("/proc/" + name + "/environ")
		if env["DISPLAY"] == "" && env["WAYLAND_DISPLAY"] == "" {
			continue
		}
		// A process that also knows the session bus (and, on X11, the
		// Xauthority file) is the best source.
		if env["DBUS_SESSION_BUS_ADDRESS"] != "" && (env["WAYLAND_DISPLAY"] != "" || env["XAUTHORITY"] != "") {
			return env
		}
		if fallback == nil {
			fallback = env
		}
	}
	return fallback
}

func readProcEnv(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 256<<10))
	if err != nil {
		return nil
	}
	env := map[string]string{}
	for _, kv := range strings.Split(string(data), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			env[k] = v
		}
	}
	return env
}
