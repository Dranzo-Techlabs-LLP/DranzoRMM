package posture

import (
	"context"
	"sort"
	"strings"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Socket types and the IPv4 address family as numbered on every supported OS.
const (
	sockStream = 1
	sockDgram  = 2
	afINET     = 2
)

// RawConn is one socket as reported by the OS.
type RawConn struct {
	Family     uint32
	Type       uint32
	IP         string
	Port       uint32
	RemotePort uint32
	Status     string
	Pid        int32
}

// FilterListening keeps the listening sockets: TCP sockets in state LISTEN
// and UDP sockets bound to a port without a peer. Wildcard addresses are
// written "0.0.0.0" / "::". The result is de-duplicated, sorted by port and
// capped at limit entries.
func FilterListening(conns []RawConn, procName func(pid int32) string, limit int) []protocol.ListeningPort {
	type key struct {
		proto, addr string
		port        int
		proc        string
	}
	seen := map[key]bool{}
	out := []protocol.ListeningPort{}
	for _, c := range conns {
		var proto string
		switch c.Type {
		case sockStream:
			if !strings.EqualFold(c.Status, "LISTEN") {
				continue
			}
			proto = "tcp"
		case sockDgram:
			if c.RemotePort != 0 {
				continue
			}
			proto = "udp"
		default:
			continue
		}
		if c.Port == 0 || c.Port > 65535 {
			continue
		}
		addr := strings.TrimSpace(c.IP)
		if addr == "" || addr == "*" {
			if c.Family == afINET {
				addr = "0.0.0.0"
			} else {
				addr = "::"
			}
		}
		name := ""
		if procName != nil && c.Pid > 0 {
			name = procName(c.Pid)
		}
		k := key{proto, addr, int(c.Port), name}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, protocol.ListeningPort{Protocol: proto, Address: addr, Port: int(c.Port), Process: name})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Process < b.Process
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// gatherListeningPorts lists the listening sockets through gopsutil (Linux:
// /proc; Windows: the IP helper tables; macOS: lsof, which shows only the
// agent's own sockets unless it runs as root).
func gatherListeningPorts(ctx context.Context) ([]protocol.ListeningPort, error) {
	conns, err := gnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, Unsupportedf("the socket table is not readable (%v)", err)
	}
	raw := make([]RawConn, 0, len(conns))
	for _, c := range conns {
		raw = append(raw, RawConn{
			Family:     c.Family,
			Type:       c.Type,
			IP:         c.Laddr.IP,
			Port:       c.Laddr.Port,
			RemotePort: c.Raddr.Port,
			Status:     c.Status,
			Pid:        c.Pid,
		})
	}
	names := map[int32]string{}
	procName := func(pid int32) string {
		if n, ok := names[pid]; ok {
			return n
		}
		n := ""
		if p, err := process.NewProcessWithContext(ctx, pid); err == nil {
			if v, err := p.NameWithContext(ctx); err == nil {
				n = OneLine(v, 128)
			}
		}
		names[pid] = n
		return n
	}
	return FilterListening(raw, procName, MaxListeningPorts), nil
}

// processNames lists the names of the running processes.
func processNames(ctx context.Context) ([]string, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(procs))
	for _, p := range procs {
		if n, err := p.NameWithContext(ctx); err == nil && n != "" {
			names = append(names, n)
		}
	}
	return names, nil
}
