package posture

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// maxLockSeconds bounds a reported timeout (one week).
const maxLockSeconds = 7 * 24 * 3600

func clampSeconds(n int) int {
	if n < 0 {
		return 0
	}
	if n > maxLockSeconds {
		return maxLockSeconds
	}
	return n
}

// ---- Windows ----

// ScreenSaver holds a user's screen saver settings (the registry values
// ScreenSaveActive, ScreenSaverIsSecure and ScreenSaveTimeOut, policy key
// first, then Control Panel\Desktop).
type ScreenSaver struct {
	Active         bool
	Secure         bool
	TimeoutSeconds int
}

// ParseRegFlag reads a "0" / "1" registry string.
func ParseRegFlag(s string) bool { return strings.TrimSpace(s) == "1" }

// ParseRegSeconds reads a registry string holding a number of seconds.
func ParseRegSeconds(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return clampSeconds(n)
}

// WindowsScreenLock combines the two mechanisms that lock a Windows session
// automatically:
//
//   - the machine inactivity limit (HKLM ... Policies\System
//     InactivityTimeoutSecs, 0 / absent = not set), machine-wide;
//   - the console user's password-protected screen saver.
//
// The shortest enabled one is reported. ok is false when neither is known
// (no machine limit and no logged-in user whose settings could be read):
// the caller then reports the section as unsupported instead of guessing.
func WindowsScreenLock(inactivitySeconds uint64, saver *ScreenSaver) (lock *protocol.ScreenLock, ok bool) {
	best := 0
	if inactivitySeconds > 0 {
		if inactivitySeconds > maxLockSeconds {
			inactivitySeconds = maxLockSeconds
		}
		best = int(inactivitySeconds)
	}
	if saver != nil && saver.Active && saver.Secure && saver.TimeoutSeconds > 0 {
		if best == 0 || saver.TimeoutSeconds < best {
			best = saver.TimeoutSeconds
		}
	}
	if best > 0 {
		return &protocol.ScreenLock{Enabled: true, TimeoutSeconds: best}, true
	}
	if saver == nil {
		return nil, false
	}
	return &protocol.ScreenLock{Enabled: false, TimeoutSeconds: 0}, true
}

// ---- macOS ----

var screenLockDelayRe = regexp.MustCompile(`screenLock delay is (\d+) seconds?`)

// ParseSysadminctlScreenLock parses `sysadminctl -screenLock status` (the
// "require password after sleep or screen saver begins" setting):
//
//	screenLock is off
//	screenLock delay is immediate
//	screenLock delay is 300 seconds
func ParseSysadminctlScreenLock(out string) (delaySeconds int, off, ok bool) {
	switch {
	case strings.Contains(out, "screenLock is off"):
		return 0, true, true
	case strings.Contains(out, "screenLock delay is immediate"):
		return 0, false, true
	}
	if m := screenLockDelayRe.FindStringSubmatch(out); m != nil {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			return clampSeconds(n), false, true
		}
	}
	return 0, false, false
}

var displaySleepRe = regexp.MustCompile(`(?m)^\s*displaysleep\s+(\d+)`)

// ParsePmsetDisplaySleep reads the display sleep timer (minutes, 0 = never)
// from `pmset -g`.
func ParsePmsetDisplaySleep(out string) (minutes int, ok bool) {
	m := displaySleepRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// MacScreenLock computes when an idle Mac locks: the screen saver starts
// after saverIdleSeconds, or the display sleeps after displaySleepMinutes
// (whichever is first and not 0 = never), and the password is required
// delaySeconds after that. A saverIdleSeconds of 0 also stands for "not
// set": the system default is not assumed, the display sleep timer is used.
func MacScreenLock(lockOff bool, delaySeconds, saverIdleSeconds, displaySleepMinutes int) *protocol.ScreenLock {
	if lockOff {
		return &protocol.ScreenLock{Enabled: false, TimeoutSeconds: 0}
	}
	idle := 0
	if saverIdleSeconds > 0 {
		idle = saverIdleSeconds
	}
	if d := displaySleepMinutes * 60; d > 0 && (idle == 0 || d < idle) {
		idle = d
	}
	if idle == 0 {
		// The password is required, but the machine never becomes idle-locked.
		return &protocol.ScreenLock{Enabled: false, TimeoutSeconds: 0}
	}
	return &protocol.ScreenLock{Enabled: true, TimeoutSeconds: clampSeconds(idle + delaySeconds)}
}

// ---- Linux (GNOME) ----

// ParseGsettingsUint parses `gsettings get` output for an unsigned value
// ("uint32 300").
func ParseGsettingsUint(out string) (int, bool) {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) == 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[len(f)-1], 10, 32)
	if err != nil {
		return 0, false
	}
	return clampSeconds(int(n)), true
}

// ParseGsettingsBool parses `gsettings get` output for a boolean.
func ParseGsettingsBool(out string) (value, ok bool) {
	switch strings.TrimSpace(out) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// GnomeScreenLock computes the GNOME lock: the session goes idle after
// idleDelay seconds (0 = never) and, if lock-enabled, locks lockDelay
// seconds later.
func GnomeScreenLock(idleDelay int, lockEnabled bool, lockDelay int) *protocol.ScreenLock {
	if !lockEnabled || idleDelay <= 0 {
		return &protocol.ScreenLock{Enabled: false, TimeoutSeconds: 0}
	}
	return &protocol.ScreenLock{Enabled: true, TimeoutSeconds: clampSeconds(idleDelay + lockDelay)}
}
