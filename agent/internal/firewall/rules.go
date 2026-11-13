// Package firewall manages the host firewall rules DranzoRMM owns (policy
// check "firewall.rules") and, later, device isolation.
//
// The agent only ever touches its own rules, which are visible in the OS
// firewall tools: Windows Firewall group "DranzoRMM", nftables table
// "inet dranzormm", pf anchor "com.apple/250.DranzoRMM". Rule rendering and
// parsing are pure functions in this untagged file and tested with fixtures.
package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Limits.
const (
	MaxRules     = 100
	MaxPorts     = 32
	MaxAddresses = 64
	MaxProgram   = 260
)

// Names of what the agent owns in the OS firewall.
const (
	WindowsGroup = "DranzoRMM"
	NftTable     = "dranzormm"
	PfAnchor     = "com.apple/250.DranzoRMM"
	labelPrefix  = "dranzo:"
)

// Rule is one firewall rule from a policy.
type Rule struct {
	Name            string   `json:"name"`
	Direction       string   `json:"direction"` // in | out
	Action          string   `json:"action"`    // allow | block
	Protocol        string   `json:"protocol"`  // tcp | udp | any
	Ports           []string `json:"ports,omitempty"`
	RemoteAddresses []string `json:"remoteAddresses,omitempty"`
	Program         string   `json:"program,omitempty"` // Windows only
}

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}$`)
	programRe = regexp.MustCompile(`^[A-Za-z]:\\[^<>"|?*\x00-\x1f]+$`)
	idRe      = regexp.MustCompile(`dranzo:([0-9a-f]{16})`)
)

// ParseRules reads and validates the "rules" parameter.
func ParseRules(raw any) ([]Rule, error) {
	if raw == nil {
		return nil, errors.New("rules is required")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, errors.New("rules must be a list of rules")
	}
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("at most %d rules", MaxRules)
	}
	for i := range rules {
		if err := rules[i].normalize(); err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i+1, rules[i].Name, err)
		}
	}
	return rules, nil
}

func (r *Rule) normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	if !nameRe.MatchString(r.Name) {
		return errors.New("name must be 1-64 letters, digits, spaces or ._()-")
	}
	r.Direction, r.Action, r.Protocol = strings.ToLower(r.Direction), strings.ToLower(r.Action), strings.ToLower(r.Protocol)
	if r.Direction != "in" && r.Direction != "out" {
		return errors.New("direction must be in or out")
	}
	if r.Action != "allow" && r.Action != "block" {
		return errors.New("action must be allow or block")
	}
	switch r.Protocol {
	case "tcp", "udp":
	case "any", "":
		r.Protocol = "any"
		if len(r.Ports) > 0 {
			return errors.New("ports need protocol tcp or udp")
		}
	default:
		return errors.New("protocol must be tcp, udp or any")
	}
	if len(r.Ports) > MaxPorts {
		return fmt.Errorf("at most %d ports", MaxPorts)
	}
	ports := make([]string, 0, len(r.Ports))
	for _, p := range r.Ports {
		n, err := normalizePort(p)
		if err != nil {
			return err
		}
		ports = append(ports, n)
	}
	r.Ports = sortedUnique(ports)
	if len(r.RemoteAddresses) > MaxAddresses {
		return fmt.Errorf("at most %d remote addresses", MaxAddresses)
	}
	addrs := make([]string, 0, len(r.RemoteAddresses))
	for _, a := range r.RemoteAddresses {
		p, err := parseAddress(a)
		if err != nil {
			return err
		}
		addrs = append(addrs, p.String())
	}
	r.RemoteAddresses = sortedUnique(addrs)
	r.Program = strings.TrimSpace(r.Program)
	if r.Program != "" && (len(r.Program) > MaxProgram || !programRe.MatchString(r.Program)) {
		return errors.New(`program must be a full Windows path such as C:\Program Files\App\app.exe`)
	}
	if r.Direction == "out" && r.Action == "block" && len(r.Ports) == 0 && len(r.RemoteAddresses) == 0 && r.Program == "" {
		return errors.New("blocking all outgoing traffic would cut the device off; use device isolation instead")
	}
	return nil
}

func normalizePort(p string) (string, error) {
	p = strings.TrimSpace(p)
	lo, hi, isRange := strings.Cut(p, "-")
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b := a
	var err2 error
	if isRange {
		b, err2 = strconv.Atoi(strings.TrimSpace(hi))
	}
	if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
		return "", fmt.Errorf("invalid port %q (use 443 or 8000-8100)", p)
	}
	if a == b {
		return strconv.Itoa(a), nil
	}
	return strconv.Itoa(a) + "-" + strconv.Itoa(b), nil
}

func parseAddress(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func sortedUnique(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// ID is a stable 16-hex fingerprint of the rule's content.
func (r Rule) ID() string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		r.Name, r.Direction, r.Action, r.Protocol, strings.Join(r.Ports, ","), strings.Join(r.RemoteAddresses, ","), strings.ToLower(r.Program),
	}, "|")))
	return hex.EncodeToString(h[:8])
}

// Applicable splits rules into those this OS can apply and those it skips
// (program rules exist only on Windows). Duplicates are removed.
func Applicable(rules []Rule, windows bool) (apply []Rule, skipped []string) {
	seen := map[string]bool{}
	for _, r := range rules {
		if r.Program != "" && !windows {
			skipped = append(skipped, r.Name)
			continue
		}
		if !seen[r.ID()] {
			seen[r.ID()] = true
			apply = append(apply, r)
		}
	}
	return apply, skipped
}

// Diff compares the IDs in place with the wanted rules.
func Diff(owned []string, want []Rule) (missing []Rule, unexpected []string) {
	have := map[string]bool{}
	for _, id := range owned {
		have[id] = true
	}
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[r.ID()] = true
		if !have[r.ID()] {
			missing = append(missing, r)
		}
	}
	for id := range have {
		if !wanted[id] {
			unexpected = append(unexpected, id)
		}
	}
	sort.Strings(unexpected)
	return missing, unexpected
}

// ParseOwnedIDs extracts rule IDs from any listing that carries "dranzo:<id>"
// markers (nft comments, pf labels, Windows descriptions).
func ParseOwnedIDs(out string) []string {
	var ids []string
	for _, m := range idRe.FindAllStringSubmatch(out, -1) {
		ids = append(ids, m[1])
	}
	return sortedUnique(ids)
}

func split(addrs []string) (v4, v6 []string) {
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	return v4, v6
}

// ---- nftables ----

// RenderNft returns an nft script that atomically replaces table inet dranzormm.
// Chains run at priority -10, before the distribution's own firewall.
func RenderNft(rules []Rule) string {
	var in, out []string
	for _, r := range rules {
		for _, line := range nftLines(r) {
			if r.Direction == "in" {
				in = append(in, line)
			} else {
				out = append(out, line)
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", NftTable, NftTable, NftTable)
	for _, ch := range []struct {
		name, hook string
		lines      []string
	}{{"input", "input", in}, {"output", "output", out}} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority -10; policy accept;\n", ch.name, ch.hook)
		for _, l := range ch.lines {
			b.WriteString("\t\t" + l + "\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func nftSet(items []string) string { return "{ " + strings.Join(items, ", ") + " }" }

func nftLines(r Rule) []string {
	dir := "saddr"
	if r.Direction == "out" {
		dir = "daddr"
	}
	proto := ""
	switch {
	case r.Protocol != "any" && len(r.Ports) > 0:
		proto = r.Protocol + " dport " + nftSet(r.Ports)
	case r.Protocol != "any":
		proto = "meta l4proto " + r.Protocol
	}
	verdict := "drop"
	if r.Action == "allow" {
		verdict = "accept"
	}
	tail := fmt.Sprintf("counter %s comment \"%s%s\"", verdict, labelPrefix, r.ID())
	join := func(parts ...string) string {
		var p []string
		for _, s := range parts {
			if s != "" {
				p = append(p, s)
			}
		}
		return strings.Join(p, " ")
	}
	v4, v6 := split(r.RemoteAddresses)
	if len(v4) == 0 && len(v6) == 0 {
		return []string{join(proto, tail)}
	}
	var lines []string
	if len(v4) > 0 {
		lines = append(lines, join("ip "+dir+" "+nftSet(v4), proto, tail))
	}
	if len(v6) > 0 {
		lines = append(lines, join("ip6 "+dir+" "+nftSet(v6), proto, tail))
	}
	return lines
}

// ---- pf (macOS) ----

// RenderPf returns the rules for the DranzoRMM pf anchor.
func RenderPf(rules []Rule) string {
	var b strings.Builder
	for _, r := range rules {
		for _, l := range pfLines(r) {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

func pfLines(r Rule) []string {
	head := "block drop " + r.Direction + " quick"
	keep := ""
	if r.Action == "allow" {
		head, keep = "pass "+r.Direction+" quick", " keep state"
	}
	proto := ""
	if r.Protocol != "any" {
		proto = " proto " + r.Protocol
	}
	port := ""
	if len(r.Ports) > 0 {
		ps := make([]string, len(r.Ports))
		for i, p := range r.Ports {
			ps[i] = strings.Replace(p, "-", ":", 1)
		}
		port = " port { " + strings.Join(ps, ", ") + " }"
	}
	label := fmt.Sprintf(" label \"%s%s\"", labelPrefix, r.ID())
	target := func(family string, addrs []string) string {
		set := "any"
		if len(addrs) > 0 {
			set = "{ " + strings.Join(addrs, ", ") + " }"
		}
		fam := ""
		if family != "" {
			fam = " " + family
		}
		if r.Direction == "in" {
			return head + fam + proto + " from " + set + " to any" + port + keep + label
		}
		return head + fam + proto + " from any to " + set + port + keep + label
	}
	v4, v6 := split(r.RemoteAddresses)
	if len(v4) == 0 && len(v6) == 0 {
		return []string{target("", nil)}
	}
	var lines []string
	if len(v4) > 0 {
		lines = append(lines, target("inet", v4))
	}
	if len(v6) > 0 {
		lines = append(lines, target("inet6", v6))
	}
	return lines
}

// ---- Windows ----

// windowsRule is the shape the PowerShell script reads from DRANZO_FW_RULES.
type windowsRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Direction string   `json:"direction"`
	Action    string   `json:"action"`
	Protocol  string   `json:"protocol"`
	Ports     []string `json:"ports"`
	Remote    []string `json:"remote"`
	Program   string   `json:"program"`
}

// WindowsPayload is the JSON handed to PSApplyRules in an environment variable
// (never in the script text).
func WindowsPayload(rules []Rule) (string, error) {
	out := make([]windowsRule, 0, len(rules))
	for _, r := range rules {
		w := windowsRule{ID: r.ID(), Name: r.Name, Direction: "Inbound", Action: "Block", Protocol: "Any",
			Ports: r.Ports, Remote: r.RemoteAddresses, Program: r.Program}
		if r.Direction == "out" {
			w.Direction = "Outbound"
		}
		if r.Action == "allow" {
			w.Action = "Allow"
		}
		if r.Protocol != "any" {
			w.Protocol = strings.ToUpper(r.Protocol)
		}
		if w.Ports == nil {
			w.Ports = []string{}
		}
		if w.Remote == nil {
			w.Remote = []string{}
		}
		out = append(out, w)
	}
	b, err := json.Marshal(out)
	return string(b), err
}
