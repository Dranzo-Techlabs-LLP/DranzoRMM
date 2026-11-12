package inventory

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// This file holds the pure parsing / filtering logic of the collectors. It
// has no build tags so that the parsers for all three OSes are unit-tested
// with fixtures on any development machine.

// Partition is one mounted filesystem as reported by the OS.
type Partition struct {
	Device     string
	MountPoint string
	FSType     string
}

var linuxRealFS = map[string]struct{}{
	"ext2": {}, "ext3": {}, "ext4": {}, "xfs": {}, "btrfs": {}, "zfs": {}, "f2fs": {},
	"vfat": {}, "exfat": {}, "ntfs": {}, "ntfs3": {}, "fuseblk": {}, "reiserfs": {},
	"jfs": {}, "bcachefs": {}, "nilfs2": {},
}

var darwinRealFS = map[string]struct{}{
	"apfs": {}, "hfs": {}, "exfat": {}, "msdos": {}, "ntfs": {},
}

var windowsRealFS = map[string]struct{}{
	"ntfs": {}, "refs": {}, "fat32": {}, "fat": {}, "exfat": {},
}

// FilterPartitions keeps only real, user-relevant filesystems for the given
// OS family and drops pseudo filesystems, snap / loop mounts and the internal
// macOS system volumes. Each device is reported once.
func FilterPartitions(family string, parts []Partition) []Partition {
	seen := map[string]struct{}{}
	var out []Partition
	for _, p := range parts {
		fs := strings.ToLower(p.FSType)
		keep := false
		switch family {
		case protocol.OSLinux:
			_, keep = linuxRealFS[fs]
			if strings.HasPrefix(p.Device, "/dev/loop") ||
				strings.HasPrefix(p.MountPoint, "/snap/") ||
				strings.HasPrefix(p.MountPoint, "/var/lib/snapd/") ||
				strings.HasPrefix(p.MountPoint, "/var/lib/docker/") ||
				strings.HasPrefix(p.MountPoint, "/var/lib/kubelet/") ||
				strings.HasPrefix(p.MountPoint, "/run/") ||
				// Containers bind-mount single files such as /etc/hosts from the host disk.
				strings.HasPrefix(p.MountPoint, "/etc/") {
				keep = false
			}
			// The root of a container is an overlay; report it so the device has a disk.
			if fs == "overlay" && p.MountPoint == "/" {
				keep = true
			}
		case protocol.OSMacOS:
			_, real := darwinRealFS[fs]
			keep = real && (p.MountPoint == "/" || strings.HasPrefix(p.MountPoint, "/Volumes/"))
		case protocol.OSWindows:
			_, keep = windowsRealFS[fs]
		}
		if !keep {
			continue
		}
		key := p.Device
		if key == "" {
			key = p.MountPoint
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

// RawInterface is one network interface as reported by the OS.
type RawInterface struct {
	Name     string
	MAC      string
	Loopback bool
	Up       bool
	Addrs    []string // CIDR or plain IP strings
}

// FilterInterfaces converts raw interfaces to the inventory form. Loopback
// and down interfaces are skipped, as are interfaces without any routable
// address (link-local only), which removes the many virtual interfaces
// modern systems create.
func FilterInterfaces(raw []RawInterface) []protocol.NetworkInterface {
	out := []protocol.NetworkInterface{}
	for _, r := range raw {
		if r.Loopback || !r.Up {
			continue
		}
		nic := protocol.NetworkInterface{Name: r.Name, MAC: strings.ToLower(r.MAC), IPv4: []string{}, IPv6: []string{}}
		for _, a := range r.Addrs {
			ipStr := a
			if i := strings.IndexByte(a, '/'); i >= 0 {
				ipStr = a[:i]
			}
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				nic.IPv4 = append(nic.IPv4, v4.String())
			} else {
				nic.IPv6 = append(nic.IPv6, ip.String())
			}
		}
		if len(nic.IPv4) == 0 && len(nic.IPv6) == 0 {
			continue
		}
		out = append(out, nic)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- macOS ----

// ParseSwVers parses the output of `sw_vers`.
func ParseSwVers(output string) (name, version, build string) {
	for _, line := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "ProductName":
			name = v
		case "ProductVersion":
			version = v
		case "BuildVersion":
			build = v
		}
	}
	return name, version, build
}

// Hardware is the identity of the physical (or virtual) machine.
type Hardware struct {
	Serial       string
	Manufacturer string
	Model        string
}

// ParseSystemProfilerHardware parses `system_profiler SPHardwareDataType -json`.
func ParseSystemProfilerHardware(data []byte) (Hardware, error) {
	var doc struct {
		Items []struct {
			MachineName  string `json:"machine_name"`
			MachineModel string `json:"machine_model"`
			ModelNumber  string `json:"model_number"`
			Serial       string `json:"serial_number"`
		} `json:"SPHardwareDataType"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Hardware{}, fmt.Errorf("parse system_profiler output: %w", err)
	}
	if len(doc.Items) == 0 {
		return Hardware{}, fmt.Errorf("system_profiler returned no hardware data")
	}
	it := doc.Items[0]
	model := it.MachineName
	switch {
	case model == "":
		model = it.MachineModel
	case it.MachineModel != "":
		model += " (" + it.MachineModel + ")"
	}
	return Hardware{Serial: CleanHardwareString(it.Serial), Manufacturer: "Apple Inc.", Model: model}, nil
}

// ---- Linux ----

// ParseOSRelease parses /etc/os-release (KEY=value, optionally quoted).
func ParseOSRelease(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
			v = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(v)
		}
		out[k] = v
	}
	return out
}

// LinuxOSInfo builds the OS section from a parsed os-release and the kernel release.
func LinuxOSInfo(osRelease map[string]string, kernel string) protocol.OSInfo {
	name := osRelease["NAME"]
	if name == "" {
		name = "Linux"
	}
	version := osRelease["VERSION_ID"]
	build := osRelease["BUILD_ID"]
	if build == "" {
		build = osRelease["VERSION"]
	}
	return protocol.OSInfo{Family: protocol.OSLinux, Name: name, Version: version, Build: build, Kernel: kernel}
}

var dmiPlaceholders = map[string]struct{}{
	"": {}, "none": {}, "n/a": {}, "na": {}, "0": {}, "default string": {},
	"to be filled by o.e.m.": {}, "to be filled by oem": {}, "not specified": {},
	"not applicable": {}, "system product name": {}, "system manufacturer": {},
	"system serial number": {}, "unknown": {}, "oem": {}, "empty": {},
	"not available": {}, "chassis serial number": {},
}

// CleanHardwareString trims a DMI / firmware string and blanks the well-known
// placeholder values vendors leave in unpopulated fields.
func CleanHardwareString(s string) string {
	s = strings.TrimSpace(strings.Trim(s, "\x00"))
	if _, placeholder := dmiPlaceholders[strings.ToLower(s)]; placeholder {
		return ""
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// TimezoneFromLink derives the IANA zone name from the target of the
// /etc/localtime symlink (".../zoneinfo/Europe/Berlin" -> "Europe/Berlin").
func TimezoneFromLink(target string) string {
	const marker = "zoneinfo/"
	i := strings.LastIndex(target, marker)
	if i < 0 {
		return ""
	}
	tz := strings.Trim(target[i+len(marker):], "/")
	tz = strings.TrimPrefix(tz, "posix/")
	tz = strings.TrimPrefix(tz, "right/")
	return tz
}

// ---- Windows ----

// WindowsOSInfo builds the OS section from the values of
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion. Windows 11 still
// reports ProductName "Windows 10 ..."; the build number decides.
func WindowsOSInfo(productName, displayVersion, releaseID, buildNumber string, ubr uint64) protocol.OSInfo {
	name := strings.TrimSpace(productName)
	if b, err := strconv.Atoi(strings.TrimSpace(buildNumber)); err == nil && b >= 22000 &&
		strings.HasPrefix(name, "Windows 10") && !strings.Contains(name, "Server") {
		name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	if name == "" {
		name = "Windows"
	}
	version := strings.TrimSpace(displayVersion)
	if version == "" {
		version = strings.TrimSpace(releaseID)
	}
	build := strings.TrimSpace(buildNumber)
	kernel := ""
	if build != "" {
		kernel = "10.0." + build
		build = build + "." + strconv.FormatUint(ubr, 10)
	}
	return protocol.OSInfo{Family: protocol.OSWindows, Name: name, Version: version, Build: build, Kernel: kernel}
}

// ParseWindowsHardwareJSON parses the JSON emitted by the CIM query the
// Windows collector runs: {"serial":"..","manufacturer":"..","model":".."}.
// (PowerShell may prefix the output with a UTF-8 byte order mark.)
func ParseWindowsHardwareJSON(data []byte) (Hardware, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	var doc struct {
		Serial       *string `json:"serial"`
		Manufacturer *string `json:"manufacturer"`
		Model        *string `json:"model"`
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return Hardware{}, fmt.Errorf("parse CIM output: %w", err)
	}
	get := func(p *string) string {
		if p == nil {
			return ""
		}
		return CleanHardwareString(*p)
	}
	return Hardware{Serial: get(doc.Serial), Manufacturer: get(doc.Manufacturer), Model: get(doc.Model)}, nil
}
