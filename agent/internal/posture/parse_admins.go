package posture

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// AdminAccount is one member of the local administrators group.
type AdminAccount struct {
	// Name is the account name. Windows: local accounts without the computer
	// prefix ("jane"), domain principals qualified ("CONTOSO\Domain Admins").
	Name string
	// SID is the security identifier (Windows; empty when only the
	// "net localgroup" fallback was available).
	SID string
	// Class is "User" or "Group" (Windows; may be empty).
	Class string
	// Builtin marks the built-in administrator: the RID 500 account on
	// Windows, root on macOS and Linux.
	Builtin bool
	// Groups are the administrator groups the account is a supplementary
	// member of (Unix: "sudo", "wheel", "admin").
	Groups []string
	// Primary marks an account that is an administrator through its primary
	// group or uid 0 (Linux), which a group-membership edit cannot change.
	Primary bool
}

// AdminNames returns the sorted, de-duplicated account names.
func AdminNames(admins []AdminAccount) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, a := range admins {
		if a.Name == "" || seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		names = append(names, a.Name)
	}
	sort.Strings(names)
	return names
}

func sortAdmins(a []AdminAccount) {
	sort.SliceStable(a, func(i, j int) bool { return a[i].Name < a[j].Name })
}

// ---- Windows ----

// AdministratorsSID is the well-known SID of the local Administrators group
// (its name is localised, the SID is not).
const AdministratorsSID = "S-1-5-32-544"

type winAdminMember struct {
	Name        string `json:"name"`
	SID         string `json:"sid"`
	ObjectClass string `json:"objectClass"`
	Source      string `json:"source"`
}

type winAdminReport struct {
	Computer     string               `json:"computer"`
	Members      list[winAdminMember] `json:"members"`
	Error        string               `json:"error"`
	NetOutput    string               `json:"netOutput"`
	BuiltinAdmin string               `json:"builtinAdmin"`
}

// StripLocalPrefix removes "COMPUTER\" (or ".\") from a local account name.
func StripLocalPrefix(name, computer string) string {
	domain, account, found := strings.Cut(name, `\`)
	if !found {
		return name
	}
	if domain == "." || (computer != "" && strings.EqualFold(domain, computer)) {
		return account
	}
	return name
}

// isBuiltinAdminSID reports whether sid is a machine or domain RID 500
// account (the built-in Administrator).
func isBuiltinAdminSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, "-500")
}

// ParseWindowsAdmins turns the output of PSLocalAdmins into accounts.
func ParseWindowsAdmins(data []byte) ([]AdminAccount, error) {
	var r winAdminReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("local administrators: %w", err)
	}
	builtin := strings.TrimSpace(r.BuiltinAdmin)
	out := []AdminAccount{}
	switch {
	case r.Members.Set:
		for _, m := range r.Members.Items {
			name := StripLocalPrefix(strings.TrimSpace(m.Name), r.Computer)
			if name == "" {
				name = strings.TrimSpace(m.SID) // orphaned SID without a name
			}
			if name == "" {
				continue
			}
			local := !strings.Contains(name, `\`)
			out = append(out, AdminAccount{
				Name:    name,
				SID:     strings.TrimSpace(m.SID),
				Class:   strings.TrimSpace(m.ObjectClass),
				Builtin: isBuiltinAdminSID(m.SID) && local,
			})
		}
	case strings.TrimSpace(r.NetOutput) != "":
		for _, name := range ParseNetLocalGroup(r.NetOutput) {
			name = StripLocalPrefix(name, r.Computer)
			out = append(out, AdminAccount{Name: name, Builtin: builtin != "" && strings.EqualFold(name, builtin)})
		}
	default:
		return nil, Unsupportedf("the members of the local Administrators group are not readable (%s)", OneLine(r.Error, 300))
	}
	sortAdmins(out)
	return out, nil
}

// ParseNetLocalGroup parses `net localgroup <group>`:
//
//	Alias name     Administrators
//	Comment        ...
//
//	Members
//
//	-------------------------------------------------------------------------------
//	Administrator
//	CONTOSO\Domain Admins
//	jane
//	The command completed successfully.
//
// The members are the lines between the dashed rule and the closing status
// line (the labels are localised, the layout is not).
func ParseNetLocalGroup(out string) []string {
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	start := -1
	for i, l := range lines {
		if t := strings.TrimSpace(l); len(t) >= 10 && strings.Trim(t, "-") == "" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var members []string
	for _, l := range lines[start:] {
		if t := strings.TrimSpace(l); t != "" {
			members = append(members, t)
		}
	}
	if len(members) == 0 {
		return nil
	}
	// The last non-empty line is the status message.
	return members[:len(members)-1]
}

// ---- macOS ----

// ParseDsclGroupMembership parses `dscl . -read /Groups/admin
// GroupMembership` ("GroupMembership: root alice").
func ParseDsclGroupMembership(out string) ([]AdminAccount, error) {
	s := strings.TrimSpace(out)
	rest, ok := strings.CutPrefix(s, "GroupMembership:")
	if !ok {
		if strings.Contains(s, "No such key") {
			return []AdminAccount{}, nil
		}
		return nil, errors.New("unrecognised dscl output")
	}
	admins := []AdminAccount{}
	seen := map[string]bool{}
	for _, name := range strings.Fields(rest) {
		if seen[name] {
			continue
		}
		seen[name] = true
		admins = append(admins, AdminAccount{Name: name, Builtin: name == "root", Groups: []string{"admin"}})
	}
	sortAdmins(admins)
	return admins, nil
}

// ---- Linux ----

// LinuxAdminGroups are the groups whose members are administrators through
// the default sudoers configuration of the supported distributions (sudo:
// Debian / Ubuntu; wheel: RHEL / Fedora; admin: older Ubuntu).
var LinuxAdminGroups = []string{"sudo", "wheel", "admin"}

// ParseLinuxAdmins lists the administrators from the content of /etc/passwd
// and /etc/group: the members of the sudo, wheel and admin groups (both
// supplementary members and accounts whose primary group is one of them) and
// every uid 0 account. Custom sudoers rules and directory services (LDAP,
// SSSD) are not evaluated.
func ParseLinuxAdmins(passwd, group string) []AdminAccount {
	adminGID := map[string]string{} // gid -> group name
	byName := map[string]*AdminAccount{}
	get := func(name string) *AdminAccount {
		if a, ok := byName[name]; ok {
			return a
		}
		a := &AdminAccount{Name: name}
		byName[name] = a
		return a
	}
	isAdminGroup := func(name string) bool {
		for _, g := range LinuxAdminGroups {
			if g == name {
				return true
			}
		}
		return false
	}
	for _, line := range strings.Split(group, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 || !isAdminGroup(f[0]) {
			continue
		}
		adminGID[f[2]] = f[0]
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				a := get(m)
				if !contains(a.Groups, f[0]) {
					a.Groups = append(a.Groups, f[0])
				}
			}
		}
	}
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 || f[0] == "" || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], "+") || strings.HasPrefix(f[0], "-") {
			continue
		}
		if f[2] == "0" {
			a := get(f[0])
			a.Primary = true
			a.Builtin = f[0] == "root"
		}
		if _, ok := adminGID[f[3]]; ok {
			get(f[0]).Primary = true
		}
	}
	out := make([]AdminAccount, 0, len(byName))
	for _, a := range byName {
		sort.Strings(a.Groups)
		out = append(out, *a)
	}
	sortAdmins(out)
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
