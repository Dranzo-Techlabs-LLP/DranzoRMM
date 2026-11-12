package posture

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Antivirus sources (PROTOCOL.md section 7.3).
const (
	SourceWSC      = "wsc"
	SourceDefender = "defender"
	SourceXProtect = "xprotect"
	SourceClamAV   = "clamav"
	SourceKnownAV  = "known_av"
)

// Product names the agent itself assigns.
const (
	NameDefender   = "Microsoft Defender Antivirus"
	NameXProtect   = "XProtect"
	NameGatekeeper = "Gatekeeper"
	NameClamAV     = "ClamAV"
)

// SignatureMaxAge is how old antivirus signatures may be to count as up to
// date where the product does not say so itself (Defender without Security
// Center, ClamAV).
const SignatureMaxAge = 7 * 24 * time.Hour

// ---- Windows ----

// DecodeProductState decodes the productState of a Windows Security Center
// product (AntiVirusProduct / FirewallProduct). The value is three bytes:
//
//	0xPPSSUU  PP = product type, SS = scanner state, UU = signature state
//
// SS 0x10 / 0x11 means real-time protection is on (0x00 / 0x01 off, 0x20 /
// 0x21 snoozed, which counts as off). UU 0x00 means the signatures are up to
// date (0x10 out of date).
func DecodeProductState(state uint32) (enabled, upToDate bool) {
	enabled = (state>>8)&0xF0 == 0x10
	upToDate = state&0xF0 == 0
	return enabled, upToDate
}

// IsDefenderName reports whether a product name is Microsoft Defender
// Antivirus (called "Windows Defender" by older Windows versions).
func IsDefenderName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "windows defender") || strings.Contains(n, "microsoft defender")
}

type wscProduct struct {
	DisplayName  string `json:"displayName"`
	ProductState int64  `json:"productState"`
}

type defenderStatus struct {
	AntivirusEnabled          bool   `json:"antivirusEnabled"`
	RealTimeProtectionEnabled bool   `json:"realTimeProtectionEnabled"`
	SignatureVersion          string `json:"signatureVersion"`
	SignatureLastUpdated      string `json:"signatureLastUpdated"`
	RunningMode               string `json:"runningMode"`
}

type winAntivirusReport struct {
	WSC           list[wscProduct] `json:"wsc"`
	WSCError      string           `json:"wscError"`
	Defender      *defenderStatus  `json:"defender"`
	DefenderError string           `json:"defenderError"`
}

func productStateBits(v int64) uint32 {
	if v < 0 || v > 0xFFFFFF {
		return 0
	}
	return uint32(v)
}

// ParseWindowsAntivirus turns the output of PSAntivirus into products.
// Security Center is authoritative where it exists (client editions); on
// Server editions, where it does not, Microsoft Defender's own status is used.
func ParseWindowsAntivirus(data []byte, now time.Time) ([]protocol.AntivirusProduct, error) {
	var r winAntivirusReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("antivirus status: %w", err)
	}
	if r.WSC.Set && len(r.WSC.Items) > 0 {
		byName := map[string]int{}
		var out []protocol.AntivirusProduct
		for _, p := range r.WSC.Items {
			name := strings.TrimSpace(p.DisplayName)
			if name == "" {
				continue
			}
			enabled, upToDate := DecodeProductState(productStateBits(p.ProductState))
			item := protocol.AntivirusProduct{Name: name, Enabled: enabled, UpToDate: upToDate, Source: SourceWSC}
			if IsDefenderName(name) && r.Defender != nil {
				item.SignatureVersion = r.Defender.SignatureVersion
			}
			// Security Center can list one product twice (stale registration):
			// keep the entry that is enabled.
			if i, dup := byName[strings.ToLower(name)]; dup {
				if item.Enabled && !out[i].Enabled {
					out[i] = item
				}
				continue
			}
			byName[strings.ToLower(name)] = len(out)
			out = append(out, item)
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if r.Defender != nil {
		d := r.Defender
		item := protocol.AntivirusProduct{
			Name:             NameDefender,
			Enabled:          d.AntivirusEnabled && d.RealTimeProtectionEnabled,
			SignatureVersion: d.SignatureVersion,
			Source:           SourceDefender,
		}
		if t, err := time.Parse(time.RFC3339Nano, d.SignatureLastUpdated); err == nil {
			age := now.Sub(t)
			item.UpToDate = age <= SignatureMaxAge
		}
		return []protocol.AntivirusProduct{item}, nil
	}
	if r.WSC.Set {
		// Security Center answered and knows no product; Defender is absent.
		return []protocol.AntivirusProduct{}, nil
	}
	return nil, Unsupportedf("neither Windows Security Center nor Microsoft Defender status is available (%s)",
		OneLine(strings.Trim(r.WSCError+"; "+r.DefenderError, "; "), 300))
}

// ---- macOS ----

// ParseGatekeeperStatus parses `spctl --status` ("assessments enabled" /
// "assessments disabled").
func ParseGatekeeperStatus(out string) (enabled, ok bool) {
	s := strings.ToLower(out)
	switch {
	case strings.Contains(s, "assessments enabled"):
		return true, true
	case strings.Contains(s, "assessments disabled"):
		return false, true
	}
	return false, false
}

// HigherVersion returns the higher of two dotted numeric versions ("" is the
// lowest).
func HigherVersion(a, b string) string {
	if compareVersions(a, b) >= 0 {
		return a
	}
	return b
}

func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

// MacAntivirus assembles the macOS products.
//
//   - XProtect (built into macOS, cannot be switched off) is listed with its
//     data version when the bundle is found. UpToDate reports whether macOS is
//     set to install XProtect data automatically (the "ConfigDataInstall"
//     software update preference; on unless explicitly disabled): the agent
//     cannot know Apple's latest version, so it reports the update mechanism.
//   - Gatekeeper is listed as its own entry (source "xprotect") carrying the
//     state of `spctl --status`, because the protocol's antivirus entry has no
//     detail field. It is not an antivirus product; the antivirus policy check
//     ignores it when deciding compliance.
//   - known lists third-party products found by DetectKnownAV.
func MacAntivirus(xprotectVersion string, configDataInstall *bool, gatekeeper *bool, known []protocol.AntivirusProduct) []protocol.AntivirusProduct {
	out := []protocol.AntivirusProduct{}
	if xprotectVersion != "" {
		out = append(out, protocol.AntivirusProduct{
			Name:             NameXProtect,
			Enabled:          true,
			UpToDate:         configDataInstall == nil || *configDataInstall,
			SignatureVersion: xprotectVersion,
			Source:           SourceXProtect,
		})
	}
	if gatekeeper != nil {
		out = append(out, protocol.AntivirusProduct{Name: NameGatekeeper, Enabled: *gatekeeper, UpToDate: true, Source: SourceXProtect})
	}
	return append(out, known...)
}

// ---- Linux ----

// ClamAV is the observed state of a ClamAV installation.
type ClamAV struct {
	// Installed: a ClamAV binary or signature database exists.
	Installed bool
	// ClamdRunning: the scanning daemon (clamd) is running.
	ClamdRunning bool
	// FreshclamRunning: the signature updater daemon is running.
	FreshclamRunning bool
	// Version and Built describe the daily signature database.
	Version string
	Built   time.Time
}

// ParseClamAVHeader parses the 512-byte header of a ClamAV database file
// (daily.cvd / daily.cld):
//
//	ClamAV-VDB:07 Nov 2026 04-26 -0500:27812:2067589:90:<md5>:<dsig>:<builder>:<stime>
func ParseClamAVHeader(header []byte) (version string, built time.Time, ok bool) {
	if len(header) > 512 {
		header = header[:512]
	}
	s := string(header)
	if !strings.HasPrefix(s, "ClamAV-VDB:") {
		return "", time.Time{}, false
	}
	parts := strings.Split(strings.TrimRight(s, " \x00\r\n"), ":")
	if len(parts) < 3 {
		return "", time.Time{}, false
	}
	version = strings.TrimSpace(parts[2])
	if _, err := strconv.ParseUint(version, 10, 32); err != nil {
		return "", time.Time{}, false
	}
	// The trailing field is the build time as Unix seconds (newer databases).
	if len(parts) >= 9 {
		if sec, err := strconv.ParseInt(strings.TrimSpace(parts[8]), 10, 64); err == nil && sec > 0 {
			return version, time.Unix(sec, 0).UTC(), true
		}
	}
	if t, err := time.Parse("02 Jan 2006 15-04 -0700", strings.TrimSpace(parts[1])); err == nil {
		return version, t.UTC(), true
	}
	return version, time.Time{}, true
}

// ClamAVProduct turns the observed state into a product entry: enabled while
// clamd is running, up to date while the daily database is younger than
// SignatureMaxAge.
func ClamAVProduct(c ClamAV, now time.Time) protocol.AntivirusProduct {
	p := protocol.AntivirusProduct{Name: NameClamAV, Enabled: c.ClamdRunning, SignatureVersion: c.Version, Source: SourceClamAV}
	if !c.Built.IsZero() {
		p.UpToDate = now.Sub(c.Built) <= SignatureMaxAge
	}
	return p
}

// ---- known third-party products (macOS, Linux) ----

// KnownAV describes how one third-party endpoint protection product is
// recognised: by an installed path and / or by the name of a running
// process. Detection is read-only (os.Stat and the process list).
type KnownAV struct {
	Name string
	// Paths are application bundles or installation directories.
	Paths []string
	// Processes are daemon process names (compared case-insensitively on the
	// first 15 characters, the length the kernels keep).
	Processes []string
}

// KnownAVDarwin is the table of third-party products detected on macOS.
var KnownAVDarwin = []KnownAV{
	{Name: "CrowdStrike Falcon", Paths: []string{"/Applications/Falcon.app", "/Library/CS/falcond"}, Processes: []string{"falcond", "com.crowdstrike.falcon.Agent"}},
	{Name: "SentinelOne", Paths: []string{"/Applications/SentinelOne/SentinelOne Extensions.app", "/Library/Sentinel/sentinel-agent.bundle"}, Processes: []string{"sentineld", "SentinelAgent"}},
	{Name: "Sophos", Paths: []string{"/Applications/Sophos/Sophos Endpoint.app", "/Applications/Sophos Endpoint.app", "/Applications/Sophos Home.app", "/Library/Sophos Anti-Virus"}, Processes: []string{"SophosScanD", "SophosServiceManager", "SophosAntiVirus"}},
	{Name: "Microsoft Defender for Endpoint", Paths: []string{"/Applications/Microsoft Defender.app", "/Applications/Microsoft Defender ATP.app"}, Processes: []string{"wdavdaemon"}},
	{Name: "Bitdefender", Paths: []string{"/Applications/Bitdefender", "/Library/Bitdefender/AVP", "/Applications/Endpoint Security for Mac.app"}, Processes: []string{"BDLDaemon", "bdldaemon", "EndpointSecurityforMac"}},
	{Name: "ESET", Paths: []string{"/Applications/ESET Endpoint Security.app", "/Applications/ESET Endpoint Antivirus.app", "/Applications/ESET Cyber Security.app", "/Applications/ESET Cyber Security Pro.app"}, Processes: []string{"esets_daemon", "com.eset.endpoint", "com.eset.devices"}},
	{Name: "Malwarebytes", Paths: []string{"/Applications/Malwarebytes.app", "/Library/Application Support/Malwarebytes/MBAM"}, Processes: []string{"RTProtectionDaemon", "FrontendAgent"}},
	{Name: "Jamf Protect", Paths: []string{"/Applications/JamfProtect.app"}, Processes: []string{"JamfProtect"}},
	{Name: "Trend Micro", Paths: []string{"/Applications/TrendMicroSecurity.app", "/Library/Application Support/TrendMicro"}, Processes: []string{"iCoreService", "TmccMac"}},
	{Name: "Avast", Paths: []string{"/Applications/Avast.app", "/Applications/Avast Security.app"}, Processes: []string{"com.avast.daemon"}},
	{Name: "AVG", Paths: []string{"/Applications/AVGAntivirus.app", "/Applications/AVG AntiVirus.app"}, Processes: []string{"com.avg.daemon"}},
	{Name: "Norton", Paths: []string{"/Applications/Norton 360.app", "/Applications/Norton Security.app", "/Applications/Norton.app"}, Processes: []string{"SymDaemon", "com.norton.mes.endpointsecurity"}},
	{Name: "McAfee / Trellix", Paths: []string{"/Applications/McAfee Endpoint Security for Mac.app", "/Applications/Trellix Endpoint Security for Mac.app", "/usr/local/McAfee", "/Library/McAfee"}, Processes: []string{"VShieldScanner", "masvc", "fmpd"}},
}

// KnownAVLinux is the table of third-party products detected on Linux.
var KnownAVLinux = []KnownAV{
	{Name: "CrowdStrike Falcon", Paths: []string{"/opt/CrowdStrike/falconctl"}, Processes: []string{"falcon-sensor", "falcond"}},
	{Name: "SentinelOne", Paths: []string{"/opt/sentinelone"}, Processes: []string{"sentinelone-agent", "s1-agent"}},
	{Name: "Sophos", Paths: []string{"/opt/sophos-spl", "/opt/sophos-av"}, Processes: []string{"sophos_managementagent", "savd", "sophos_threat_detector"}},
	{Name: "Microsoft Defender for Endpoint", Paths: []string{"/opt/microsoft/mdatp"}, Processes: []string{"wdavdaemon"}},
	{Name: "Bitdefender", Paths: []string{"/opt/bitdefender-security-tools", "/opt/BitDefender"}, Processes: []string{"bdsecd"}},
	{Name: "ESET", Paths: []string{"/opt/eset"}, Processes: []string{"esets_daemon"}},
	{Name: "Malwarebytes", Paths: []string{"/opt/malwarebytes"}, Processes: []string{"mbdaemon"}},
	{Name: "Trend Micro", Paths: []string{"/opt/ds_agent", "/opt/TrendMicro"}, Processes: []string{"ds_agent"}},
	{Name: "Avast", Paths: []string{"/usr/bin/avast", "/etc/avast"}, Processes: []string{"avast"}},
	{Name: "McAfee / Trellix", Paths: []string{"/opt/McAfee", "/opt/isec", "/opt/Trellix"}, Processes: []string{"mfetpd", "mfeespd", "masvc"}},
}

// procNameLen is how many characters of a process name the kernels keep
// (Linux TASK_COMM_LEN - 1, macOS MAXCOMLEN - 1 in practice).
const procNameLen = 15

func procKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if len(n) > procNameLen {
		n = n[:procNameLen]
	}
	return n
}

// DetectKnownAV matches the table against the file system and the running
// processes. A product is listed when it is installed or running; Enabled
// means its daemon is running. The agent cannot read a third-party product's
// signature state, so for source "known_av" UpToDate simply mirrors Enabled
// ("not known to be outdated") and SignatureVersion is empty.
func DetectKnownAV(table []KnownAV, exists func(path string) bool, procs []string) []protocol.AntivirusProduct {
	running := make(map[string]bool, len(procs))
	for _, p := range procs {
		if k := procKey(p); k != "" {
			running[k] = true
		}
	}
	var out []protocol.AntivirusProduct
	for _, k := range table {
		installed, active := false, false
		for _, p := range k.Paths {
			if exists != nil && exists(p) {
				installed = true
				break
			}
		}
		for _, p := range k.Processes {
			if running[procKey(p)] {
				active = true
				break
			}
		}
		if !installed && !active {
			continue
		}
		out = append(out, protocol.AntivirusProduct{Name: k.Name, Enabled: active, UpToDate: active, Source: SourceKnownAV})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// HasProcess reports whether a process with that name is running.
func HasProcess(procs []string, name string) bool {
	want := procKey(name)
	for _, p := range procs {
		if procKey(p) == want {
			return true
		}
	}
	return false
}
