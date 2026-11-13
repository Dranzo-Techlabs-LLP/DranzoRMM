package firewall

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Isolation names. The macOS anchor sorts before the rules anchor (250), so a
// "pass quick" policy rule cannot punch through an isolation; nftables drops
// win across tables anyway, and Windows block rules win over allow rules.
const (
	NftIsolationTable     = "dranzormm_isolation"
	PfIsolationAnchor     = "com.apple/200.DranzoRMMIsolation"
	WindowsIsolationGroup = "DranzoRMM Isolation"
)

// SortAddrs orders and de-duplicates addresses.
func SortAddrs(in []netip.Addr) []netip.Addr {
	m := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range in {
		a = a.Unmap()
		if a.IsValid() && !m[a] {
			m[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func splitAddrs(allow []netip.Addr) (v4, v6 []string) {
	for _, a := range SortAddrs(allow) {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	return v4, v6
}

// RenderIsolationNft returns the nft script for table inet dranzormm_isolation:
// both chains drop by default; loopback, DHCP, DNS and the allowed hosts pass.
// Inbound DNS answers must belong to a connection the device opened.
func RenderIsolationNft(allow []netip.Addr) string {
	v4, v6 := splitAddrs(allow)
	var in, out []string
	in = append(in, `iif "lo" accept`)
	out = append(out, `oif "lo" accept`)
	if len(v4) > 0 {
		in = append(in, "ip saddr "+nftSet(v4)+" accept")
		out = append(out, "ip daddr "+nftSet(v4)+" accept")
	}
	if len(v6) > 0 {
		in = append(in, "ip6 saddr "+nftSet(v6)+" accept")
		out = append(out, "ip6 daddr "+nftSet(v6)+" accept")
	}
	in = append(in,
		"udp sport 67 udp dport 68 accept",
		"udp sport 53 ct state established accept",
		"tcp sport 53 ct state established accept",
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept",
	)
	out = append(out,
		"udp dport { 53, 67 } accept",
		"tcp dport 53 accept",
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept",
	)
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", NftIsolationTable, NftIsolationTable, NftIsolationTable)
	for _, ch := range []struct {
		name  string
		lines []string
	}{{"input", in}, {"output", out}} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority -20; policy drop;\n", ch.name, ch.name)
		for _, l := range ch.lines {
			b.WriteString("\t\t" + l + "\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// RenderIsolationPf returns the rules of the macOS isolation anchor.
func RenderIsolationPf(allow []netip.Addr) string {
	v4, v6 := splitAddrs(allow)
	lines := []string{"pass quick on lo0 all"}
	if len(v4) > 0 {
		set := "{ " + strings.Join(v4, ", ") + " }"
		lines = append(lines, "pass out quick inet from any to "+set+" keep state", "pass in quick inet from "+set+" to any keep state")
	}
	if len(v6) > 0 {
		set := "{ " + strings.Join(v6, ", ") + " }"
		lines = append(lines, "pass out quick inet6 from any to "+set+" keep state", "pass in quick inet6 from "+set+" to any keep state")
	}
	lines = append(lines,
		"pass out quick proto udp from any to any port { 53, 67 } keep state",
		"pass out quick proto tcp from any to any port 53 keep state",
		"pass in quick proto udp from any port 67 to any port 68",
		"pass quick inet6 proto icmp6 all icmp6-type { neighbrsol, neighbradv, routersol, routeradv }",
		"block drop quick all",
	)
	return strings.Join(lines, "\n") + "\n"
}

// ComplementRanges returns "first-last" ranges covering every address of the
// family except the allowed ones (and loopback), for Windows Firewall block
// rules: a block rule wins over any allow rule, so blocking "everything but"
// is how an allow-list is enforced there.
func ComplementRanges(allow []netip.Addr, v6 bool) []string {
	var first, last netip.Addr
	var keep []netip.Addr
	if v6 {
		first, last = netip.IPv6Unspecified(), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
		keep = append(keep, netip.IPv6Loopback())
	} else {
		first, last = netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255")
	}
	for _, a := range SortAddrs(allow) {
		if a.Is6() == v6 {
			keep = append(keep, a)
		}
	}
	type span struct{ lo, hi netip.Addr }
	var holes []span
	for _, a := range SortAddrs(keep) {
		holes = append(holes, span{a, a})
	}
	if !v6 {
		holes = append(holes, span{netip.MustParseAddr("127.0.0.0"), netip.MustParseAddr("127.255.255.255")})
		sort.Slice(holes, func(i, j int) bool { return holes[i].lo.Less(holes[j].lo) })
	}
	var out []string
	cur := first
	for _, h := range holes {
		if h.hi.Less(cur) {
			continue
		}
		if cur.Less(h.lo) {
			out = append(out, rangeString(cur, h.lo.Prev()))
		}
		next := h.hi.Next()
		if !next.IsValid() {
			return out
		}
		cur = next
	}
	if cur.Less(last) || cur == last {
		out = append(out, rangeString(cur, last))
	}
	return out
}

func rangeString(lo, hi netip.Addr) string {
	if lo == hi {
		return lo.String()
	}
	return lo.String() + "-" + hi.String()
}
