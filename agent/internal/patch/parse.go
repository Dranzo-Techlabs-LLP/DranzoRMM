package patch

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/software"
)

// ---- apt ----

// AptUpgrade is one upgradable package.
type AptUpgrade struct {
	Name           string
	CurrentVersion string
	NewVersion     string
	Arch           string
	// Origin is the suite list ("stable-security,stable-updates") or the
	// origin description ("Debian-Security:12/stable-security").
	Origin   string
	Security bool
}

var (
	// libssl3/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]
	aptUpgradableRe = regexp.MustCompile(`^([^/\s]+)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from:\s+(\S+)\]`)
	// Inst libssl3 [3.0.14-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
	aptInstRe = regexp.MustCompile(`^Inst (\S+) \[([^\]]+)\] \((\S+)([^)]*)\)`)
)

// aptSecurity reports whether a suite or origin names a security archive
// (Debian "stable-security" / "Debian-Security", Ubuntu "jammy-security",
// Ubuntu Pro "esm-infra-security").
func aptSecurity(origin string) bool {
	return strings.Contains(strings.ToLower(origin), "security")
}

// ParseAptUpgradable parses "apt list --upgradable".
func ParseAptUpgradable(out string) []AptUpgrade {
	var ups []AptUpgrade
	for _, l := range software.Lines(out) {
		m := aptUpgradableRe.FindStringSubmatch(l)
		if m == nil {
			continue // "Listing...", warnings
		}
		ups = append(ups, AptUpgrade{Name: m[1], Origin: m[2], NewVersion: m[3], Arch: m[4], CurrentVersion: m[5], Security: aptSecurity(m[2])})
	}
	return ups
}

// ParseAptSimulate parses the "Inst" lines of "apt-get -s dist-upgrade".
// Lines without a current version are new dependencies, not updates.
func ParseAptSimulate(out string) []AptUpgrade {
	var ups []AptUpgrade
	for _, l := range software.Lines(out) {
		m := aptInstRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		origin := strings.TrimSpace(m[4])
		arch := ""
		if i := strings.LastIndex(origin, "["); i >= 0 && strings.HasSuffix(origin, "]") {
			arch = origin[i+1 : len(origin)-1]
			origin = strings.TrimSpace(origin[:i])
		}
		ups = append(ups, AptUpgrade{Name: m[1], CurrentVersion: m[2], NewVersion: m[3], Arch: arch, Origin: origin, Security: aptSecurity(origin)})
	}
	return ups
}

// ParseAptHistoryLast returns the time of the last finished apt transaction
// from the content of /var/log/apt/history.log ("End-Date: 2024-05-01  10:11:12",
// local time).
func ParseAptHistoryLast(content string, loc *time.Location) (time.Time, bool) {
	var last time.Time
	found := false
	for _, l := range software.Lines(content) {
		v, ok := strings.CutPrefix(l, "End-Date:")
		if !ok {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Join(strings.Fields(v), " "), loc)
		if err != nil {
			continue
		}
		last, found = t, true
	}
	return last, found
}

// ---- dnf ----

// DnfUpdate is one line of "dnf check-update".
type DnfUpdate struct {
	Name    string
	Arch    string
	Version string
	Repo    string
}

// NameArch is the "name.arch" form dnf accepts as a package spec.
func (u DnfUpdate) NameArch() string { return u.Name + "." + u.Arch }

var rpmArches = map[string]bool{
	"x86_64": true, "aarch64": true, "noarch": true, "i686": true, "i386": true, "i586": true,
	"ppc64le": true, "ppc64": true, "s390x": true, "armv7hl": true, "riscv64": true, "src": true,
}

func splitNameArch(s string) (name, arch string, ok bool) {
	i := strings.LastIndexByte(s, '.')
	if i <= 0 || !rpmArches[s[i+1:]] {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ParseDnfCheckUpdate parses "dnf -q check-update": three columns
// (name.arch, version, repository). A long name wraps: the name stands alone
// and the other two columns follow on an indented line. The "Obsoleting
// Packages" section and informational lines are not updates.
func ParseDnfCheckUpdate(out string) []DnfUpdate {
	var ups []DnfUpdate
	add := func(nameArch, version, repo string) {
		name, arch, ok := splitNameArch(nameArch)
		if !ok || version == "" || version[0] < '0' || version[0] > '9' {
			return
		}
		ups = append(ups, DnfUpdate{Name: name, Arch: arch, Version: version, Repo: repo})
	}
	wrapped := ""
	for _, l := range software.Lines(out) {
		if strings.HasPrefix(l, "Obsoleting Packages") {
			break
		}
		f := strings.Fields(l)
		indented := strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")
		switch {
		case len(f) == 3 && !indented:
			add(f[0], f[1], f[2])
			wrapped = ""
		case len(f) == 1 && !indented:
			wrapped = f[0]
		case len(f) == 2 && indented && wrapped != "":
			add(wrapped, f[0], f[1])
			wrapped = ""
		default:
			wrapped = ""
		}
	}
	return ups
}

var severityRank = map[string]int{SeverityUnspecified: 0, SeverityLow: 1, SeverityModerate: 2, SeverityImportant: 3, SeverityCritical: 4}

// normalizeSeverity maps a vendor severity word (MSRC and Red Hat use the
// same scale) to the reported vocabulary.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "important", "high":
		return SeverityImportant
	case "moderate", "medium":
		return SeverityModerate
	case "low":
		return SeverityLow
	}
	return SeverityUnspecified
}

// ParseDnfUpdateinfo parses "dnf -q updateinfo list --security"
// ("RLSA-2024:1234 Important/Sec. openssl-1:3.0.7-25.el9_3.x86_64") into the
// highest security severity per "name.arch".
func ParseDnfUpdateinfo(out string) map[string]string {
	sev := map[string]string{}
	for _, l := range software.Lines(out) {
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		kind := strings.ToLower(f[1])
		word, isSec := strings.CutSuffix(kind, "/sec.")
		if !isSec {
			if kind != "security" {
				continue
			}
			word = ""
		}
		// name-[epoch:]version-release.arch
		nvr, arch, ok := splitNameArch(f[2])
		if !ok {
			continue
		}
		i := strings.LastIndexByte(nvr, '-')
		if i <= 0 {
			continue
		}
		j := strings.LastIndexByte(nvr[:i], '-')
		if j <= 0 {
			continue
		}
		key := nvr[:j] + "." + arch
		s := normalizeSeverity(word)
		if cur, seen := sev[key]; !seen || severityRank[s] > severityRank[cur] {
			sev[key] = s
		}
	}
	return sev
}

// ---- macOS softwareupdate ----

// SoftwareUpdateItem is one entry of "softwareupdate --list".
type SoftwareUpdateItem struct {
	// Label is what "softwareupdate --install" takes.
	Label       string
	Title       string
	Version     string
	SizeBytes   int64
	Recommended bool
	Restart     bool
}

var (
	// Old format (macOS 10.14 and earlier), second line:
	//	Security Update 2019-004 (10.13.6), 1942411K [recommended] [restart]
	suOldDetailRe = regexp.MustCompile(`^(.*) \(([^()]*)\), (\d+)K(.*)$`)
	suSizeRe      = regexp.MustCompile(`^(\d+)\s*(K|KiB)?$`)
)

func parseSUSize(s string) int64 {
	m := suSizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n < 0 || n > 1<<40 {
		return 0
	}
	return n * 1024
}

// parseSUDetail fills the item from the line that follows its label.
func parseSUDetail(item *SoftwareUpdateItem, line string) {
	line = strings.TrimSpace(line)
	if rest, ok := strings.CutPrefix(line, "Title: "); ok {
		// New format: "Title: X, Version: 14.6.1, Size: 1568310KiB, Recommended: YES, Action: restart,"
		// The title itself may contain commas, so the known keys are located from the right.
		segments := strings.Split(rest, ", ")
		titleEnd := len(segments)
		for i, seg := range segments {
			k, v, ok := strings.Cut(strings.TrimSuffix(strings.TrimSpace(seg), ","), ": ")
			if !ok {
				continue
			}
			known := true
			switch k {
			case "Version":
				item.Version = v
			case "Size":
				item.SizeBytes = parseSUSize(v)
			case "Recommended":
				item.Recommended = strings.EqualFold(v, "YES")
			case "Action":
				item.Restart = strings.EqualFold(v, "restart")
			default:
				known = false
			}
			if known && i < titleEnd {
				titleEnd = i
			}
		}
		item.Title = strings.TrimSuffix(strings.TrimSpace(strings.Join(segments[:titleEnd], ", ")), ",")
		return
	}
	if m := suOldDetailRe.FindStringSubmatch(line); m != nil {
		item.Title = m[1]
		item.Version = m[2]
		item.SizeBytes = parseSUSize(m[3] + "K")
		item.Recommended = strings.Contains(m[4], "[recommended]")
		item.Restart = strings.Contains(m[4], "[restart]")
	}
}

// ParseSoftwareUpdateList parses "softwareupdate --list" in both the old
// format ("   * Label" / "<tab>Title (version), 123K [recommended] [restart]")
// and the format used since macOS 10.15 ("* Label: ..." / "<tab>Title: ...,
// Version: ..., Size: ...KiB, Recommended: YES, Action: restart,").
func ParseSoftwareUpdateList(out string) []SoftwareUpdateItem {
	var items []SoftwareUpdateItem
	lines := software.Lines(out)
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		rest, ok := strings.CutPrefix(t, "* ")
		if !ok {
			continue
		}
		label := strings.TrimSpace(strings.TrimPrefix(rest, "Label: "))
		if label == "" {
			continue
		}
		item := SoftwareUpdateItem{Label: label, Title: label}
		if i+1 < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "* ") {
			parseSUDetail(&item, lines[i+1])
			if item.Title == "" {
				item.Title = label
			}
		}
		items = append(items, item)
	}
	return items
}

// softwareUpdateCategory classifies a macOS update by its title.
func softwareUpdateCategory(title string) string {
	t := strings.ToLower(title)
	switch {
	case strings.Contains(t, "security") || strings.Contains(t, "xprotect") || strings.Contains(t, "gatekeeper") || strings.Contains(t, "mrt"):
		return CategorySecurity
	case strings.Contains(t, "command line tools"):
		return CategoryTool
	case strings.HasPrefix(t, "macos") || strings.HasPrefix(t, "mac os") || strings.HasPrefix(t, "os x"):
		return CategoryUpdate
	}
	return CategoryApplication
}

// Phrases softwareupdate prints when an update needs an authorisation the
// agent cannot give. On Apple Silicon, installing a macOS update requires a
// volume owner's password (or an MDM bootstrap token); root alone is not
// enough.
var suAuthPhrases = []string{
	"failed to authenticate",
	"authentication failed",
	"not authorized",
	"not authorised",
	"volume owner",
	"requires authentication",
	"password:",
	"bootstrap token",
	"user is required",
}

// Phrases that mean the installation did not happen.
var suFailPhrases = []string{
	"no such update",
	"no updates are available",
	"is not available",
	"error installing",
	"failed to download",
	"download failed",
	"installation failed",
	"cancelled",
}

// SoftwareUpdateFailure inspects the output of "softwareupdate --install"
// and returns a clear reason when the update was not installed, "" when no
// failure is visible. softwareupdate does not reliably signal these cases
// through its exit code.
func SoftwareUpdateFailure(output string) string {
	lower := strings.ToLower(output)
	for _, p := range suAuthPhrases {
		if strings.Contains(lower, p) {
			return "this update needs the authorisation of a volume owner (Apple Silicon); it cannot be installed unattended without MDM"
		}
	}
	for _, p := range suFailPhrases {
		if strings.Contains(lower, p) {
			return "softwareupdate did not install the update (" + p + ")"
		}
	}
	return ""
}

// ---- Homebrew ----

// BrewOutdated is one outdated formula or cask.
type BrewOutdated struct {
	Name      string
	Installed string
	Current   string
	Cask      bool
	Pinned    bool
}

// flexStrings accepts a JSON array of strings, a single string or null
// (older Homebrew versions report a cask's installed version as a string).
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*f = list
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*f = []string{one}
	return nil
}

type brewOutdatedEntry struct {
	Name              string      `json:"name"`
	InstalledVersions flexStrings `json:"installed_versions"`
	CurrentVersion    string      `json:"current_version"`
	Pinned            bool        `json:"pinned"`
}

// ParseBrewOutdated parses "brew outdated --json=v2".
func ParseBrewOutdated(data string) ([]BrewOutdated, error) {
	start := strings.IndexByte(data, '{')
	if start < 0 {
		return nil, errors.New("brew outdated printed no JSON")
	}
	var doc struct {
		Formulae []brewOutdatedEntry `json:"formulae"`
		Casks    []brewOutdatedEntry `json:"casks"`
	}
	if err := json.NewDecoder(strings.NewReader(data[start:])).Decode(&doc); err != nil {
		return nil, err
	}
	var out []BrewOutdated
	conv := func(list []brewOutdatedEntry, cask bool) {
		for _, e := range list {
			if e.Name == "" {
				continue
			}
			installed := ""
			if n := len(e.InstalledVersions); n > 0 {
				installed = e.InstalledVersions[n-1]
			}
			out = append(out, BrewOutdated{Name: e.Name, Installed: installed, Current: e.CurrentVersion, Cask: cask, Pinned: e.Pinned})
		}
	}
	conv(doc.Formulae, false)
	conv(doc.Casks, true)
	return out, nil
}
