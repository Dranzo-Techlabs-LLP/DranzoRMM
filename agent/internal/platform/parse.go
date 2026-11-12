package platform

import (
	"sort"
	"strings"
)

// ParseWho extracts the distinct user names from `who` output (Linux and macOS).
func ParseWho(output string) []string {
	seen := map[string]struct{}{}
	var users []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if name == "" || name == "reboot" || name == "LOGIN" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		users = append(users, name)
	}
	sort.Strings(users)
	return users
}

// ParseLoginctlSessionIDs extracts the session ids from
// `loginctl list-sessions --no-legend`.
func ParseLoginctlSessionIDs(output string) []string {
	var ids []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		if !validSessionID(id) {
			continue
		}
		ids = append(ids, id)
		if len(ids) >= 256 {
			break
		}
	}
	return ids
}

func validSessionID(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '_' {
			return false
		}
	}
	return true
}

// LoginSession is one logind session as shown by `loginctl show-session`.
type LoginSession struct {
	Name   string
	Active bool
	Remote bool
	Class  string
	Type   string
	Seat   string
	State  string
}

// ParseLoginctlSession parses the KEY=VALUE output of
// `loginctl show-session <id> -p Name -p Active -p Remote -p Class -p Type -p Seat -p State`.
func ParseLoginctlSession(output string) LoginSession {
	var s LoginSession
	for _, line := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "Name":
			s.Name = v
		case "Active":
			s.Active = v == "yes"
		case "Remote":
			s.Remote = v == "yes"
		case "Class":
			s.Class = v
		case "Type":
			s.Type = v
		case "Seat":
			s.Seat = v
		case "State":
			s.State = v
		}
	}
	return s
}

// PickConsoleUser chooses the console user from logind sessions: the active,
// local, regular-user session on a seat. Graphical sessions win over text consoles.
func PickConsoleUser(sessions []LoginSession) string {
	best := ""
	for _, s := range sessions {
		if s.Name == "" || !s.Active || s.Remote || s.Class != "user" || s.Seat == "" {
			continue
		}
		if s.Type == "x11" || s.Type == "wayland" || s.Type == "mir" {
			return s.Name
		}
		if best == "" {
			best = s.Name
		}
	}
	return best
}

// LoggedInFromSessions lists the distinct users of regular logind sessions.
func LoggedInFromSessions(sessions []LoginSession) []string {
	seen := map[string]struct{}{}
	var users []string
	for _, s := range sessions {
		if s.Name == "" || s.Class != "user" || s.State == "closing" {
			continue
		}
		if _, dup := seen[s.Name]; dup {
			continue
		}
		seen[s.Name] = struct{}{}
		users = append(users, s.Name)
	}
	sort.Strings(users)
	return users
}

// PasswdEntry is one line of passwd(5) (also the output of `getent passwd <name>`).
type PasswdEntry struct {
	Name  string
	UID   string
	GID   string
	Home  string
	Shell string
}

// ParsePasswdLine parses "name:x:uid:gid:gecos:home:shell".
func ParsePasswdLine(line string) (PasswdEntry, bool) {
	parts := strings.Split(strings.TrimSpace(line), ":")
	if len(parts) < 7 || parts[0] == "" || !isDigits(parts[2]) || !isDigits(parts[3]) {
		return PasswdEntry{}, false
	}
	return PasswdEntry{Name: parts[0], UID: parts[2], GID: parts[3], Home: parts[5], Shell: parts[6]}, true
}

// validAccountKey reports whether s looks like a plain account name or a
// numeric id (letters, digits, and . _ - @ $ \\; not starting with '-').
func validAccountKey(s string) bool {
	if s == "" || len(s) > 256 || s[0] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '@' || r == '$' || r == '\\':
		default:
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ParseIoregValue extracts a quoted property such as "IOPlatformUUID" or
// "IOPlatformSerialNumber" from `ioreg -rd1 -c IOPlatformExpertDevice` output.
func ParseIoregValue(output, key string) string {
	needle := `"` + key + `"`
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, needle) {
			continue
		}
		_, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			return v[1 : len(v)-1]
		}
	}
	return ""
}

// ParseMachineID normalises the content of /etc/machine-id.
func ParseMachineID(content string) string {
	id := strings.ToLower(strings.TrimSpace(content))
	if len(id) > 128 {
		id = id[:128]
	}
	return id
}

// MergeEnv overlays extra KEY=VALUE pairs on base; later values win. On
// case-insensitive platforms pass foldCase=true.
func MergeEnv(base, extra []string, foldCase bool) []string {
	norm := func(k string) string {
		if foldCase {
			return strings.ToUpper(k)
		}
		return k
	}
	index := map[string]int{}
	out := make([]string, 0, len(base)+len(extra))
	add := func(kv string) {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			// Windows keeps per-drive entries such as "=C:=C:\dir"; pass them through.
			out = append(out, kv)
			return
		}
		if i, dup := index[norm(k)]; dup {
			out[i] = kv
			return
		}
		index[norm(k)] = len(out)
		out = append(out, kv)
	}
	for _, kv := range base {
		add(kv)
	}
	for _, kv := range extra {
		add(kv)
	}
	return out
}
