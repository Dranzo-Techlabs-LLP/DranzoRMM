// Package netscan discovers devices on the local network (network.scan) and
// reads the default gateway and the active Wi-Fi connection for inventory.
//
// Parsers are pure functions in this untagged file and tested with fixtures;
// the OS-specific files only run fixed helper commands.
package netscan

import (
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Neighbor is one entry of the OS neighbor (ARP) table.
type Neighbor struct {
	IP  netip.Addr
	MAC string
}

// NormalizeMAC returns a MAC as lowercase colon-separated hex ("a4:83:e7:11:22:33"),
// or "" when s is not a 6-byte MAC. Windows writes "A4-83-E7-11-22-33" and
// macOS drops leading zeros ("a4:3:e7:...").
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "-", ":"))
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		if len(p) != 2 {
			return ""
		}
		parts[i] = p
	}
	hw, err := net.ParseMAC(strings.Join(parts, ":"))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}

// UsableMAC reports whether mac is a unicast device address: not all zeros,
// not broadcast, not multicast (IPv4 01:00:5e, IPv6 33:33, any group bit).
func UsableMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	if hw[0]&0x01 != 0 { // group (multicast/broadcast) bit
		return false
	}
	for _, b := range hw {
		if b != 0 {
			return true
		}
	}
	return false
}

// RandomizedMAC reports whether mac is locally administered, which phones and
// laptops use for private Wi-Fi addresses.
func RandomizedMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) == 6 && hw[0]&0x02 != 0
}

func neighbor(ip, mac string) (Neighbor, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return Neighbor{}, false
	}
	m := NormalizeMAC(mac)
	if m == "" || !UsableMAC(m) {
		return Neighbor{}, false
	}
	return Neighbor{IP: addr, MAC: m}, true
}

// ParseDarwinArp parses "arp -an":
//
//	? (192.168.68.1) at a4:83:e7:11:22:33 on en0 ifscope [ethernet]
//	? (192.168.68.9) at (incomplete) on en0 ifscope [ethernet]
func ParseDarwinArp(out string) []Neighbor {
	var res []Neighbor
	for _, line := range strings.Split(out, "\n") {
		open, closeIdx := strings.Index(line, "("), strings.Index(line, ")")
		at := strings.Index(line, " at ")
		if open < 0 || closeIdx < open || at < closeIdx {
			continue
		}
		rest := strings.Fields(line[at+4:])
		if len(rest) == 0 {
			continue
		}
		if n, ok := neighbor(line[open+1:closeIdx], rest[0]); ok {
			res = append(res, n)
		}
	}
	return res
}

// ParseProcNetArp parses /proc/net/arp:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.68.1     0x1         0x2         a4:83:e7:11:22:33     *        eth0
//
// Flags 0x0 means incomplete.
func ParseProcNetArp(out string) []Neighbor {
	var res []Neighbor
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[2] == "0x0" {
			continue
		}
		if n, ok := neighbor(f[0], f[3]); ok {
			res = append(res, n)
		}
	}
	return res
}

type winNeighbor struct {
	IPAddress        string `json:"IPAddress"`
	LinkLayerAddress string `json:"LinkLayerAddress"`
	State            any    `json:"State"`
}

// ParseWindowsNeighbors parses the JSON printed by PSNeighbors (one object or
// an array). Unreachable and incomplete entries are skipped.
func ParseWindowsNeighbors(out []byte) []Neighbor {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil
	}
	var list []winNeighbor
	if strings.HasPrefix(trimmed, "{") {
		var one winNeighbor
		if json.Unmarshal([]byte(trimmed), &one) != nil {
			return nil
		}
		list = []winNeighbor{one}
	} else if json.Unmarshal([]byte(trimmed), &list) != nil {
		return nil
	}
	var res []Neighbor
	for _, w := range list {
		state := strings.ToLower(strings.TrimSpace(toString(w.State)))
		if state == "unreachable" || state == "incomplete" || state == "1" || state == "0" {
			continue
		}
		if n, ok := neighbor(w.IPAddress, w.LinkLayerAddress); ok {
			res = append(res, n)
		}
	}
	return res
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// NetNeighbor State as a number: 0 Unreachable, 1 Incomplete, 2 Probe, 3 Delay, 4 Stale, 5 Reachable, 6 Permanent.
		return strconv.Itoa(int(t))
	default:
		return ""
	}
}

// ---- default gateway ----

// ParseProcNetRoute returns the IPv4 default gateway from /proc/net/route
// (little-endian hex), or "".
func ParseProcNetRoute(out string) string {
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || f[1] != "00000000" || f[2] == "00000000" || len(f[2]) != 8 {
			continue
		}
		var b [4]byte
		for j := 0; j < 4; j++ {
			v, ok := hexByte(f[2][j*2 : j*2+2])
			if !ok {
				return ""
			}
			b[3-j] = v
		}
		return netip.AddrFrom4(b).String()
	}
	return ""
}

func hexByte(s string) (byte, bool) {
	var v byte
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			v |= byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= byte(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return v, true
}

// ParseDarwinRouteGet returns the gateway from "route -n get default".
func ParseDarwinRouteGet(out string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(k) == "gateway" {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil && a.Is4() {
				return a.String()
			}
		}
	}
	return ""
}

// ParseWindowsGateway returns the first IPv4 next hop printed by PSGateway.
func ParseWindowsGateway(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if a, err := netip.ParseAddr(strings.TrimSpace(line)); err == nil && a.Is4() && !a.IsUnspecified() {
			return a.String()
		}
	}
	return ""
}

// ---- Wi-Fi ----

// WiFi is the active Wi-Fi connection.
type WiFi struct {
	Interface, SSID, BSSID string
}

// cleanSSID drops the placeholders the OS prints instead of a hidden name.
func cleanSSID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "<redacted>") || strings.EqualFold(s, "<unknown ssid>") || len(s) > 64 {
		return ""
	}
	return s
}

// ParseNetshWlan parses "netsh wlan show interfaces". It returns ok=false when
// no interface is connected.
func ParseNetshWlan(out string) (WiFi, bool) {
	var w WiFi
	connected := false
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, " : ")
		if !ok {
			continue
		}
		key, val := strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch key {
		case "name":
			if connected {
				return w, true // first connected interface wins
			}
			w = WiFi{Interface: val}
		case "state":
			connected = strings.EqualFold(val, "connected")
		case "ssid":
			w.SSID = cleanSSID(val)
		case "bssid", "ap bssid":
			w.BSSID = NormalizeMAC(val)
		}
	}
	return w, connected
}

// ParseDarwinSummary parses "ipconfig getsummary <if>" for a Wi-Fi interface.
func ParseDarwinSummary(iface, out string) (WiFi, bool) {
	w := WiFi{Interface: iface}
	found := false
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " : ")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "SSID":
			w.SSID, found = cleanSSID(v), true
		case "BSSID":
			w.BSSID = NormalizeMAC(v)
		case "InterfaceType":
			if !strings.EqualFold(strings.TrimSpace(v), "WiFi") {
				return WiFi{}, false
			}
		}
	}
	return w, found
}

// ParseNmcliWifi parses "nmcli -t -f ACTIVE,SSID,BSSID,DEVICE dev wifi" where
// colons inside fields are escaped as "\:".
func ParseNmcliWifi(out string) (WiFi, bool) {
	for _, line := range strings.Split(out, "\n") {
		f := splitNmcli(strings.TrimSpace(line))
		if len(f) >= 4 && f[0] == "yes" {
			return WiFi{SSID: cleanSSID(f[1]), BSSID: NormalizeMAC(f[2]), Interface: f[3]}, true
		}
	}
	return WiFi{}, false
}

func splitNmcli(s string) []string {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case s[i] == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(fields, cur.String())
}

// ---- scan targets ----

// MaxPrefixBits is the widest subnet scanned around the agent's own address (/22: 1024 addresses).
const MaxPrefixBits = 22

// MaxInterfaces is how many interfaces are scanned.
const MaxInterfaces = 2

// ScanSubnets picks the subnets to scan from the interfaces' IPv4 prefixes:
// private or shared ranges only (never public addresses), no loopback or
// link-local, at most MaxInterfaces, each narrowed to /22 around the own address.
func ScanSubnets(prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, p := range prefixes {
		a := p.Addr()
		if !a.Is4() || a.IsLoopback() || a.IsLinkLocalUnicast() || (!a.IsPrivate() && !cgnat.Contains(a)) || p.Bits() >= 31 {
			continue
		}
		bits := p.Bits()
		if bits < MaxPrefixBits {
			bits = MaxPrefixBits
		}
		sub := netip.PrefixFrom(a, bits).Masked()
		if seen[sub] {
			continue
		}
		seen[sub] = true
		out = append(out, sub)
		if len(out) == MaxInterfaces {
			break
		}
	}
	return out
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Hosts lists the host addresses of p (no network or broadcast address),
// skipping the addresses in exclude.
func Hosts(p netip.Prefix, exclude map[netip.Addr]bool) []netip.Addr {
	p = p.Masked()
	var res []netip.Addr
	first := p.Addr()
	last := lastAddr(p)
	for a := first.Next(); a.IsValid() && a.Less(last); a = a.Next() {
		if !exclude[a] {
			res = append(res, a)
		}
	}
	return res
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	host := 32 - p.Bits()
	for i := 3; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	return netip.AddrFrom4(b)
}

// InSubnets reports whether a is inside one of subnets.
func InSubnets(a netip.Addr, subnets []netip.Prefix) bool {
	for _, s := range subnets {
		if s.Contains(a) {
			return true
		}
	}
	return false
}

// SortNeighbors orders by IP and removes duplicate IPs (last MAC wins).
func SortNeighbors(n []Neighbor) []Neighbor {
	byIP := map[netip.Addr]Neighbor{}
	for _, x := range n {
		byIP[x.IP] = x
	}
	out := make([]Neighbor, 0, len(byIP))
	for _, x := range byIP {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}
