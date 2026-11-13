package netscan

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Limits of one scan.
const (
	MaxNeighbors    = 1024
	ProbeTimeout    = 300 * time.Millisecond
	ProbeParallel   = 64
	SettleDelay     = 500 * time.Millisecond
	LookupTimeout   = 1500 * time.Millisecond
	LookupParallel  = 16
	maxHostnameSize = 253
)

// ProbePorts wake the neighbor cache: a connect attempt makes the OS resolve
// the MAC even when the port is closed. Nothing is reported about the ports.
var ProbePorts = []int{445, 80, 22}

// Scanner does one network.scan. Every dependency is injectable for tests.
type Scanner struct {
	// Prefixes returns the IPv4 prefixes of the active interfaces.
	Prefixes func() ([]netip.Prefix, error)
	// Dial opens a TCP connection (probe only; closed immediately).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Neighbors reads the OS neighbor table.
	Neighbors func(ctx context.Context) ([]Neighbor, error)
	// Gateway returns the IPv4 default gateway ("" when unknown).
	Gateway func(ctx context.Context) string
	// Lookup does reverse DNS.
	Lookup func(ctx context.Context, addr string) ([]string, error)
	// Settle is the pause between probes and reading the table (default SettleDelay).
	Settle time.Duration
	Now    func() time.Time
}

// New returns a Scanner backed by the real network and OS tables.
func New(p platform.Platform) *Scanner {
	d := &net.Dialer{Timeout: ProbeTimeout}
	return &Scanner{
		Prefixes:  InterfacePrefixes,
		Dial:      d.DialContext,
		Neighbors: func(ctx context.Context) ([]Neighbor, error) { return readNeighbors(ctx, p) },
		Gateway:   func(ctx context.Context) string { return DefaultGateway(ctx, p) },
		Lookup:    net.DefaultResolver.LookupAddr,
		Now:       time.Now,
	}
}

// InterfacePrefixes returns the IPv4 prefixes of up and non-loopback interfaces.
func InterfacePrefixes() ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(ipn.String()); err == nil && p.Addr().Is4() {
					out = append(out, p)
				}
			}
		}
	}
	return out, nil
}

// Run scans and returns the neighbors inside the scanned subnets.
func (s *Scanner) Run(ctx context.Context, resolveNames bool) (protocol.NetworkScanResult, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	res := protocol.NetworkScanResult{ScannedAt: now().UTC(), Subnets: []string{}, Neighbors: []protocol.NetworkNeighbor{}}
	prefixes, err := s.Prefixes()
	if err != nil {
		return res, err
	}
	own := map[netip.Addr]bool{}
	for _, p := range prefixes {
		own[p.Addr()] = true
	}
	subnets := ScanSubnets(prefixes)
	for _, sn := range subnets {
		res.Subnets = append(res.Subnets, sn.String())
	}
	if s.Gateway != nil {
		res.Gateway = s.Gateway(ctx)
	}
	if len(subnets) == 0 {
		return res, nil
	}

	var targets []netip.Addr
	for _, sn := range subnets {
		targets = append(targets, Hosts(sn, own)...)
	}
	s.probe(ctx, targets)
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	settle := s.Settle
	if settle == 0 {
		settle = SettleDelay
	}
	select {
	case <-ctx.Done():
		return res, ctx.Err()
	case <-time.After(settle):
	}

	table, err := s.Neighbors(ctx)
	if err != nil {
		return res, err
	}
	var found []Neighbor
	for _, n := range SortNeighbors(table) {
		if InSubnets(n.IP, subnets) && !own[n.IP] {
			found = append(found, n)
		}
	}
	if len(found) > MaxNeighbors {
		found, res.Truncated = found[:MaxNeighbors], true
	}
	names := map[netip.Addr]string{}
	if resolveNames && s.Lookup != nil {
		names = s.resolve(ctx, found)
	}
	for _, n := range found {
		res.Neighbors = append(res.Neighbors, protocol.NetworkNeighbor{
			IP: n.IP.String(), MAC: n.MAC, Hostname: names[n.IP],
			Gateway: n.IP.String() == res.Gateway, Randomized: RandomizedMAC(n.MAC),
		})
	}
	return res, nil
}

func (s *Scanner) probe(ctx context.Context, targets []netip.Addr) {
	sem := make(chan struct{}, ProbeParallel)
	var wg sync.WaitGroup
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, port := range ProbePorts {
				pctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
				conn, err := s.Dial(pctx, "tcp4", net.JoinHostPort(a.String(), strconv.Itoa(port)))
				cancel()
				if err == nil {
					_ = conn.Close()
					return
				}
				// "connection refused" means the host answered: its MAC is now in the table.
				if strings.Contains(err.Error(), "refused") {
					return
				}
			}
		}(t)
	}
	wg.Wait()
}

func (s *Scanner) resolve(ctx context.Context, found []Neighbor) map[netip.Addr]string {
	names := make(map[netip.Addr]string, len(found))
	var mu sync.Mutex
	sem := make(chan struct{}, LookupParallel)
	var wg sync.WaitGroup
	for _, n := range found {
		sem <- struct{}{}
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, LookupTimeout)
			defer cancel()
			list, err := s.Lookup(lctx, a.String())
			if err != nil || len(list) == 0 {
				return
			}
			name := strings.TrimSuffix(strings.TrimSpace(list[0]), ".")
			if name == "" || len(name) > maxHostnameSize || strings.ContainsAny(name, " \t\r\n") {
				return
			}
			mu.Lock()
			names[a] = name
			mu.Unlock()
		}(n.IP)
	}
	wg.Wait()
	return names
}
