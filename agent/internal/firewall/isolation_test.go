package firewall

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, x := range s {
		out[i] = netip.MustParseAddr(x)
	}
	return out
}

func TestRenderIsolationNftAllowsOnlyTheEssentials(t *testing.T) {
	got := RenderIsolationNft(addrs("192.168.68.102", "fd00::5", "192.168.68.102"))
	for _, want := range []string{
		"add table inet dranzormm_isolation\ndelete table inet dranzormm_isolation\n",
		"type filter hook input priority -20; policy drop;",
		"type filter hook output priority -20; policy drop;",
		`iif "lo" accept`,
		"ip saddr { 192.168.68.102 } accept",
		"ip daddr { 192.168.68.102 } accept",
		"ip6 daddr { fd00::5 } accept",
		"udp sport 53 ct state established accept",
		"udp dport { 53, 67 } accept",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// Inbound DNS is only accepted for connections the device opened.
	if strings.Contains(got, "udp sport 53 accept") {
		t.Error("unconditional inbound from port 53 would be a bypass")
	}
}

func TestRenderIsolationPfEndsWithBlockAll(t *testing.T) {
	got := RenderIsolationPf(addrs("192.168.68.102"))
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if lines[0] != "pass quick on lo0 all" || lines[len(lines)-1] != "block drop quick all" {
		t.Errorf("pf isolation:\n%s", got)
	}
	if !strings.Contains(got, "pass out quick inet from any to { 192.168.68.102 } keep state") {
		t.Errorf("server not allowed:\n%s", got)
	}
	if PfIsolationAnchor >= PfAnchor {
		t.Error("the isolation anchor must sort before the rules anchor")
	}
}

func TestComplementRanges(t *testing.T) {
	got := ComplementRanges(addrs("10.0.0.1", "192.168.1.1", "192.168.1.2"), false)
	want := []string{"0.0.0.0-10.0.0.0", "10.0.0.2-126.255.255.255", "128.0.0.0-192.168.1.0", "192.168.1.3-255.255.255.255"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("v4 complement %v", got)
	}
	if got := ComplementRanges(nil, false); strings.Join(got, ",") != "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255" {
		t.Errorf("empty allow %v", got)
	}
	if got := ComplementRanges(addrs("255.255.255.255"), false); got[len(got)-1] != "128.0.0.0-255.255.255.254" {
		t.Errorf("broadcast at the end %v", got)
	}
	v6 := ComplementRanges(addrs("fd00::5"), true)
	if len(v6) != 3 || v6[0] != "::" || v6[1] != "::2-fd00::4" || !strings.HasPrefix(v6[2], "fd00::6-") {
		t.Errorf("v6 complement %v", v6)
	}
}

type fakeIso struct {
	isolated [][]netip.Addr
	released int
}

func (f *fakeIso) Isolate(_ context.Context, allow []netip.Addr) error {
	f.isolated = append(f.isolated, allow)
	return nil
}

func (f *fakeIso) Release(context.Context) error { f.released++; return nil }

func TestIsolatorSafetyNetStateAndRestore(t *testing.T) {
	be := &fakeIso{}
	reachable := errors.New("timeout")
	iso := &Isolator{
		Backend: be, StatePath: filepath.Join(t.TempDir(), "iso.json"),
		Reachable: func(context.Context) error { return reachable },
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "rmm.example.com" {
				return addrs("203.0.113.10"), nil
			}
			return nil, errors.New("nxdomain")
		},
	}
	// Server unreachable after isolating: undone, no state saved.
	if _, err := iso.Isolate(context.Background(), "https://rmm.example.com:8443", nil); err == nil || !strings.Contains(err.Error(), "released") {
		t.Fatalf("err %v", err)
	}
	if be.released != 1 || iso.State() != nil {
		t.Fatalf("released %d state %+v", be.released, iso.State())
	}
	// Reachable: isolated with the server and the resolvable extra endpoint.
	reachable = nil
	allowed, err := iso.Isolate(context.Background(), "https://rmm.example.com:8443", []Endpoint{{Host: "10.0.0.9", Port: 443}, {Host: "gone.example.com", Port: 443}})
	if err != nil || len(allowed) != 2 {
		t.Fatalf("allowed %v err %v", allowed, err)
	}
	st := iso.State()
	if st == nil || !st.Active || strings.Join(st.Allowed, ",") != "10.0.0.9,203.0.113.10" {
		t.Fatalf("state %+v", st)
	}
	// Restore re-applies the pinned addresses without DNS.
	iso.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("restore must not resolve")
		return nil, nil
	}
	restored, err := iso.Restore(context.Background())
	if err != nil || !restored || len(be.isolated[len(be.isolated)-1]) != 2 {
		t.Fatalf("restore %v %v", restored, err)
	}
	if err := iso.Release(context.Background()); err != nil || iso.State() != nil {
		t.Fatalf("release %v", err)
	}
	if restored, _ := iso.Restore(context.Background()); restored {
		t.Error("restored after release")
	}
	// An unresolvable server is refused before anything changes.
	iso.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	before := len(be.isolated)
	if _, err := iso.Isolate(context.Background(), "https://nope.invalid", nil); err == nil || len(be.isolated) != before {
		t.Error("isolated without a resolvable server")
	}
}

func TestValidEndpoint(t *testing.T) {
	for e, ok := range map[Endpoint]bool{
		{Host: "mesh.example.com", Port: 443}: true, {Host: "192.168.68.102", Port: 8086}: true,
		{Host: "bad host", Port: 443}: false, {Host: "x", Port: 0}: false, {Host: "", Port: 1}: false,
		{Host: "a..b", Port: 1}: false, {Host: "a;rm", Port: 1}: false,
	} {
		if ValidEndpoint(e) != ok {
			t.Errorf("%+v: %v", e, !ok)
		}
	}
}
