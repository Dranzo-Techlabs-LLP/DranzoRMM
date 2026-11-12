package posture

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ---- Windows ----

type winFirewallProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type winFirewallReport struct {
	Profiles list[winFirewallProfile] `json:"profiles"`
	Active   list[string]             `json:"active"`
	Products list[wscProduct]         `json:"products"`
	Error    string                   `json:"error"`
}

// profileForCategory maps a network category (Get-NetConnectionProfile) to
// the firewall profile that applies to it.
func profileForCategory(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "domainauthenticated", "domain", "2":
		return "Domain"
	case "private", "1":
		return "Private"
	case "public", "0":
		return "Public"
	}
	return ""
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ParseWindowsFirewall turns the output of PSFirewall into the firewall
// state. The firewall counts as enabled only if every profile that is in use
// by a connected network is on; with no connected network all three profiles
// must be on. If Windows Firewall is off but a third-party firewall
// registered with Security Center is on, the host firewall is enabled (this
// is how Windows Security itself judges it). The per-profile state is in the
// detail.
func ParseWindowsFirewall(data []byte) (*protocol.FirewallState, error) {
	var r winFirewallReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("firewall status: %w", err)
	}
	if !r.Profiles.Set || len(r.Profiles.Items) == 0 {
		return nil, Unsupportedf("Windows Firewall profiles are not readable (%s)", OneLine(r.Error, 300))
	}
	state := map[string]bool{}
	var parts []string
	for _, p := range r.Profiles.Items {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		state[name] = p.Enabled
		parts = append(parts, name+": "+onOff(p.Enabled))
	}
	var active []string
	seen := map[string]bool{}
	for _, c := range r.Active.Items {
		if name := profileForCategory(c); name != "" && !seen[name] {
			seen[name] = true
			active = append(active, name)
		}
	}
	enabled := true
	if len(active) > 0 {
		for _, name := range active {
			if on, known := state[name]; !known || !on {
				enabled = false
			}
		}
	} else {
		for _, on := range state {
			if !on {
				enabled = false
			}
		}
	}
	detail := "Windows Firewall: " + strings.Join(parts, ", ")
	if len(active) > 0 {
		detail += "; active: " + strings.Join(active, ", ")
	} else {
		detail += "; no connected network"
	}
	for _, p := range r.Products.Items {
		name := strings.TrimSpace(p.DisplayName)
		if name == "" || strings.Contains(strings.ToLower(name), "windows firewall") || IsDefenderName(name) {
			continue
		}
		on, _ := DecodeProductState(productStateBits(p.ProductState))
		detail += "; third-party: " + OneLine(name, 80) + " (" + onOff(on) + ")"
		if on {
			enabled = true
		}
	}
	return &protocol.FirewallState{Enabled: enabled, Detail: detail}, nil
}

// ---- macOS ----

var alfStateRe = regexp.MustCompile(`State\s*=\s*(\d)`)

// ParseSocketFilterFW parses `socketfilterfw --getglobalstate`:
//
//	Firewall is enabled. (State = 1)
//	Firewall is disabled. (State = 0)
//
// State 2 is "block all incoming connections" (also enabled).
func ParseSocketFilterFW(out string) (*protocol.FirewallState, error) {
	s := strings.TrimSpace(out)
	if m := alfStateRe.FindStringSubmatch(s); m != nil {
		switch m[1] {
		case "0":
			return &protocol.FirewallState{Enabled: false, Detail: "Application Firewall: off (state 0)"}, nil
		case "1":
			return &protocol.FirewallState{Enabled: true, Detail: "Application Firewall: on (state 1)"}, nil
		case "2":
			return &protocol.FirewallState{Enabled: true, Detail: "Application Firewall: on, blocking all incoming connections (state 2)"}, nil
		}
	}
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "firewall is enabled"), strings.Contains(low, "firewall is on"):
		return &protocol.FirewallState{Enabled: true, Detail: "Application Firewall: on"}, nil
	case strings.Contains(low, "firewall is disabled"), strings.Contains(low, "firewall is off"):
		return &protocol.FirewallState{Enabled: false, Detail: "Application Firewall: off"}, nil
	}
	return nil, fmt.Errorf("unrecognised socketfilterfw output: %q", OneLine(s, 120))
}

// ---- Linux ----

// Probe is the result of asking one firewall tool. A nil *Probe means the
// tool is not installed.
type Probe struct {
	Output   string
	ExitCode int
	// Failed: the tool could not be run to completion.
	Failed bool
}

// LinuxFirewallProbes is everything the Linux gatherer asked.
type LinuxFirewallProbes struct {
	// UFW is `ufw status`; UFWConf the content of /etc/ufw/ufw.conf.
	UFW     *Probe
	UFWConf string
	// Firewalld is `firewall-cmd --state`.
	Firewalld *Probe
	// Nft is `nft list ruleset`.
	Nft *Probe
	// Iptables is `iptables -S INPUT` (asked only when nft is not installed).
	Iptables *Probe
}

// ParseUFWStatus parses the first line of `ufw status` ("Status: active").
func ParseUFWStatus(out string) (active, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(l, "status:") {
			continue
		}
		switch strings.TrimSpace(strings.TrimPrefix(l, "status:")) {
		case "active":
			return true, true
		case "inactive":
			return false, true
		}
	}
	return false, false
}

// ParseUFWConf reads ENABLED=yes|no from /etc/ufw/ufw.conf.
func ParseUFWConf(conf string) (enabled, ok bool) {
	for _, line := range strings.Split(conf, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		k, v, found := strings.Cut(l, "=")
		if !found || strings.TrimSpace(k) != "ENABLED" {
			continue
		}
		switch strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`)) {
		case "yes":
			return true, true
		case "no":
			return false, true
		}
	}
	return false, false
}

// ParseFirewalldState parses `firewall-cmd --state` ("running" with exit code
// 0, "not running" with exit code 252).
func ParseFirewalldState(p Probe) (running, ok bool) {
	s := strings.ToLower(strings.TrimSpace(p.Output))
	switch {
	case strings.Contains(s, "not running"):
		return false, true
	case p.ExitCode == 0 && strings.Contains(s, "running"):
		return true, true
	case p.ExitCode == 252:
		return false, true
	}
	return false, false
}

var (
	nftChainRe  = regexp.MustCompile(`^\s*chain\s+\S+\s*\{`)
	nftHookRe   = regexp.MustCompile(`\bhook\s+input\b`)
	nftPolicyRe = regexp.MustCompile(`\bpolicy\s+drop\b`)
	nftBlockRe  = regexp.MustCompile(`\b(drop|reject)\b`)
)

// ParseNftRuleset reports whether `nft list ruleset` contains input
// filtering. The documented heuristic: a base chain on the "input" hook that
// has policy drop, or that contains at least one drop / reject rule. Chains
// that only accept, NAT tables and forward chains (what container runtimes
// add) do not count.
func ParseNftRuleset(out string) bool {
	inChain, isInput := false, false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case nftChainRe.MatchString(line):
			inChain, isInput = true, false
			continue
		case strings.TrimSpace(line) == "}":
			if inChain {
				inChain, isInput = false, false
			}
			continue
		}
		if !inChain {
			continue
		}
		if nftHookRe.MatchString(line) {
			isInput = true
			if nftPolicyRe.MatchString(line) {
				return true
			}
			continue
		}
		if isInput && nftBlockRe.MatchString(line) {
			return true
		}
	}
	return false
}

// ParseIptablesInput reports whether `iptables -S INPUT` shows input
// filtering: policy DROP, or at least one DROP / REJECT rule.
func ParseIptablesInput(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "-P" && f[1] == "INPUT" && f[2] == "DROP" {
			return true
		}
		if len(f) >= 2 && f[0] == "-A" && f[1] == "INPUT" {
			for i := 2; i+1 < len(f); i++ {
				if f[i] == "-j" && (f[i+1] == "DROP" || f[i+1] == "REJECT") {
					return true
				}
			}
		}
	}
	return false
}

// LinuxFirewall combines the probes. The documented heuristic: the host
// firewall is enabled when ufw is active, or firewalld is running, or the
// nftables (or legacy iptables) rule set filters input (see ParseNftRuleset).
// If no probe says "enabled" and one of the installed tools could not be
// asked (for example nft without CAP_NET_ADMIN in a container), the state is
// unknown and an *UnsupportedError is returned instead of a guess.
func LinuxFirewall(p LinuxFirewallProbes) (*protocol.FirewallState, error) {
	enabled := false
	var parts, unknown []string

	if p.UFW != nil {
		active, ok := false, false
		if !p.UFW.Failed && p.UFW.ExitCode == 0 {
			active, ok = ParseUFWStatus(p.UFW.Output)
		}
		source := ""
		if !ok && p.UFWConf != "" {
			active, ok = ParseUFWConf(p.UFWConf)
			source = " (ufw.conf)"
		}
		switch {
		case !ok:
			unknown = append(unknown, "ufw")
			parts = append(parts, "ufw: unknown")
		case active:
			enabled = true
			parts = append(parts, "ufw: active"+source)
		default:
			parts = append(parts, "ufw: inactive"+source)
		}
	} else {
		parts = append(parts, "ufw: not installed")
	}

	if p.Firewalld != nil {
		running, ok := false, false
		if !p.Firewalld.Failed {
			running, ok = ParseFirewalldState(*p.Firewalld)
		}
		switch {
		case !ok:
			unknown = append(unknown, "firewalld")
			parts = append(parts, "firewalld: unknown")
		case running:
			enabled = true
			parts = append(parts, "firewalld: running")
		default:
			parts = append(parts, "firewalld: not running")
		}
	} else {
		parts = append(parts, "firewalld: not installed")
	}

	switch {
	case p.Nft != nil:
		switch {
		case p.Nft.Failed || p.Nft.ExitCode != 0:
			unknown = append(unknown, "nftables")
			parts = append(parts, "nftables: not readable")
		case ParseNftRuleset(p.Nft.Output):
			enabled = true
			parts = append(parts, "nftables: input filtering rules present")
		default:
			parts = append(parts, "nftables: no input filtering rules")
		}
	case p.Iptables != nil:
		switch {
		case p.Iptables.Failed || p.Iptables.ExitCode != 0:
			unknown = append(unknown, "iptables")
			parts = append(parts, "iptables: not readable")
		case ParseIptablesInput(p.Iptables.Output):
			enabled = true
			parts = append(parts, "iptables: input filtering rules present")
		default:
			parts = append(parts, "iptables: no input filtering rules")
		}
	default:
		parts = append(parts, "nftables / iptables: not installed")
	}

	if !enabled && len(unknown) > 0 {
		return nil, Unsupportedf("the firewall state cannot be determined (%s)", strings.Join(parts, "; "))
	}
	return &protocol.FirewallState{Enabled: enabled, Detail: strings.Join(parts, "; ")}, nil
}
