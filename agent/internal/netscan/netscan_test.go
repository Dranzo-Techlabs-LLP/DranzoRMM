package netscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func ips(n []Neighbor) map[string]string {
	m := map[string]string{}
	for _, x := range n {
		m[x.IP.String()] = x.MAC
	}
	return m
}

func TestNormalizeAndClassifyMAC(t *testing.T) {
	cases := map[string]string{
		"A4-83-E7-11-22-33": "a4:83:e7:11:22:33",
		"4:d9:f5:a:b:c":     "04:d9:f5:0a:0b:0c",
		"a4:83:e7:11:22":    "",
		"zz:83:e7:11:22:33": "",
		"(incomplete)":      "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
	for mac, usable := range map[string]bool{
		"a4:83:e7:11:22:33": true, "ff:ff:ff:ff:ff:ff": false, "01:00:5e:00:00:fb": false,
		"33:33:00:00:00:01": false, "00:00:00:00:00:00": false,
	} {
		if UsableMAC(mac) != usable {
			t.Errorf("UsableMAC(%s) = %v", mac, !usable)
		}
	}
	if !RandomizedMAC("da:a1:19:22:33:44") || RandomizedMAC("a4:83:e7:11:22:33") {
		t.Error("RandomizedMAC: locally administered bit not detected")
	}
}

func TestParseNeighborTables(t *testing.T) {
	darwin := ips(ParseDarwinArp(fixture(t, "arp_darwin.txt")))
	want := map[string]string{"192.168.68.1": "a4:83:e7:11:22:33", "192.168.68.106": "04:d9:f5:0a:0b:0c", "192.168.68.77": "da:a1:19:22:33:44"}
	if len(darwin) != len(want) {
		t.Fatalf("darwin: %v", darwin)
	}
	for ip, mac := range want {
		if darwin[ip] != mac {
			t.Errorf("darwin %s = %q, want %q", ip, darwin[ip], mac)
		}
	}

	linux := ips(ParseProcNetArp(fixture(t, "proc_net_arp.txt")))
	if len(linux) != 3 || linux["192.168.68.106"] != "04:d9:f5:0a:0b:0c" || linux["192.168.68.50"] != "" {
		t.Errorf("linux: %v", linux)
	}

	win := ips(ParseWindowsNeighbors([]byte(fixture(t, "neighbors_windows.json"))))
	if len(win) != 2 || win["192.168.68.1"] != "a4:83:e7:11:22:33" || win["192.168.68.102"] != "3c:22:fb:00:11:22" {
		t.Errorf("windows: %v", win)
	}
	one := ParseWindowsNeighbors([]byte(`{"IPAddress":"10.0.0.1","LinkLayerAddress":"00-11-22-33-44-55","State":5}`))
	if len(one) != 1 {
		t.Errorf("single object with numeric state: %v", one)
	}
	if ParseWindowsNeighbors([]byte(`{"IPAddress":"10.0.0.2","LinkLayerAddress":"00-11-22-33-44-56","State":1}`)) != nil {
		t.Error("numeric Incomplete state must be skipped")
	}
	if ParseWindowsNeighbors([]byte("not json")) != nil {
		t.Error("garbage must yield nothing")
	}
}

func TestParseGateways(t *testing.T) {
	if g := ParseProcNetRoute(fixture(t, "proc_net_route.txt")); g != "192.168.68.1" {
		t.Errorf("linux gateway %q", g)
	}
	if g := ParseDarwinRouteGet(fixture(t, "route_get_darwin.txt")); g != "192.168.68.1" {
		t.Errorf("darwin gateway %q", g)
	}
	if g := ParseWindowsGateway("\r\n0.0.0.0\r\n192.168.68.1\r\n10.0.0.1\r\n"); g != "192.168.68.1" {
		t.Errorf("windows gateway %q", g)
	}
	if ParseProcNetRoute("Iface\tDestination\tGateway\neth0\t00000000\tZZZZZZZZ\n") != "" {
		t.Error("bad hex must yield no gateway")
	}
}

func TestParseWiFi(t *testing.T) {
	w, ok := ParseNetshWlan(fixture(t, "netsh_wlan.txt"))
	if !ok || w.SSID != "Dranzo-Office" || w.BSSID != "a4:83:e7:11:22:40" || w.Interface != "Wi-Fi" {
		t.Errorf("netsh: %+v %v", w, ok)
	}
	if _, ok := ParseNetshWlan(fixture(t, "netsh_wlan_disconnected.txt")); ok {
		t.Error("disconnected interface reported as connected")
	}
	w, ok = ParseDarwinSummary("en0", fixture(t, "ipconfig_summary_darwin.txt"))
	if !ok || w.SSID != "" || w.BSSID != "a4:83:e7:11:22:40" {
		t.Errorf("darwin: redacted SSID must be empty, got %+v %v", w, ok)
	}
	if _, ok := ParseDarwinSummary("en5", "InterfaceType : Ethernet\nSSID : x\n"); ok {
		t.Error("ethernet interface reported as Wi-Fi")
	}
	w, ok = ParseNmcliWifi(fixture(t, "nmcli_wifi.txt"))
	if !ok || w.SSID != "Dranzo Office" || w.BSSID != "a4:83:e7:11:22:40" || w.Interface != "wlan0" {
		t.Errorf("nmcli: %+v %v", w, ok)
	}
}

func TestScanSubnetsAndHosts(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/8"),
		netip.MustParsePrefix("169.254.3.4/16"),
		netip.MustParsePrefix("8.8.8.8/24"), // public: never scanned
		netip.MustParsePrefix("10.20.30.40/16"),
		netip.MustParsePrefix("192.168.68.102/24"),
		netip.MustParsePrefix("172.16.5.1/24"), // third private interface: over the limit
	}
	got := ScanSubnets(in)
	if len(got) != 2 || got[0].String() != "10.20.28.0/22" || got[1].String() != "192.168.68.0/24" {
		t.Fatalf("subnets %v", got)
	}
	hosts := Hosts(netip.MustParsePrefix("192.168.68.0/24"), map[netip.Addr]bool{netip.MustParseAddr("192.168.68.102"): true})
	if len(hosts) != 253 || hosts[0].String() != "192.168.68.1" || hosts[len(hosts)-1].String() != "192.168.68.254" {
		t.Errorf("hosts: %d first %v last %v", len(hosts), hosts[0], hosts[len(hosts)-1])
	}
	if n := len(Hosts(netip.MustParsePrefix("10.20.28.0/22"), nil)); n != 1022 {
		t.Errorf("/22 hosts = %d", n)
	}
}

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func TestScannerProbesThenReportsOnlyScannedSubnet(t *testing.T) {
	var mu sync.Mutex
	probed := map[string]bool{}
	s := &Scanner{
		Prefixes: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.68.102/24")}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			mu.Lock()
			probed[host] = true
			mu.Unlock()
			if host == "192.168.68.1" {
				return fakeConn{}, nil
			}
			return nil, errors.New("connect: connection refused")
		},
		Neighbors: func(context.Context) ([]Neighbor, error) {
			return []Neighbor{
				{IP: netip.MustParseAddr("192.168.68.1"), MAC: "a4:83:e7:11:22:33"},
				{IP: netip.MustParseAddr("192.168.68.77"), MAC: "da:a1:19:22:33:44"},
				{IP: netip.MustParseAddr("172.17.0.2"), MAC: "02:42:ac:11:00:02"},     // other subnet
				{IP: netip.MustParseAddr("192.168.68.102"), MAC: "3c:22:fb:00:11:22"}, // the scanner itself
			}, nil
		},
		Gateway: func(context.Context) string { return "192.168.68.1" },
		Lookup: func(_ context.Context, addr string) ([]string, error) {
			if addr == "192.168.68.1" {
				return []string{"router.lan."}, nil
			}
			return nil, errors.New("no name")
		},
		Settle: time.Millisecond,
		Now:    func() time.Time { return time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC) },
	}
	res, err := s.Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(probed) != 253 || probed["192.168.68.102"] || probed["192.168.68.0"] || probed["192.168.68.255"] {
		t.Errorf("probed %d hosts (own/network/broadcast must be skipped)", len(probed))
	}
	if len(res.Subnets) != 1 || res.Subnets[0] != "192.168.68.0/24" || res.Gateway != "192.168.68.1" {
		t.Errorf("result header %+v", res)
	}
	if len(res.Neighbors) != 2 {
		t.Fatalf("neighbors %+v", res.Neighbors)
	}
	gw, phone := res.Neighbors[0], res.Neighbors[1]
	if !gw.Gateway || gw.Hostname != "router.lan" || gw.Randomized {
		t.Errorf("gateway entry %+v", gw)
	}
	if phone.Gateway || !phone.Randomized || phone.Hostname != "" {
		t.Errorf("phone entry %+v", phone)
	}
}

func TestScannerWithoutPrivateSubnetDoesNothing(t *testing.T) {
	s := &Scanner{
		Prefixes:  func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("203.0.113.5/24")}, nil },
		Dial:      func(context.Context, string, string) (net.Conn, error) { t.Fatal("must not probe"); return nil, nil },
		Neighbors: func(context.Context) ([]Neighbor, error) { t.Fatal("must not read"); return nil, nil },
	}
	res, err := s.Run(context.Background(), false)
	if err != nil || len(res.Subnets) != 0 || len(res.Neighbors) != 0 {
		t.Errorf("res %+v err %v", res, err)
	}
}
