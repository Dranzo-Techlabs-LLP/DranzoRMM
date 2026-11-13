package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
)

// IsolationBackend switches the OS-level isolation on and off.
type IsolationBackend interface {
	// Isolate allows only loopback, DHCP, DNS and allow; it replaces any earlier isolation.
	Isolate(ctx context.Context, allow []netip.Addr) error
	// Release removes the isolation.
	Release(ctx context.Context) error
}

// Endpoint is a host (name or IP) and port that stays reachable.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// IsolationState is persisted while a device is isolated.
type IsolationState struct {
	Active  bool       `json:"active"`
	Since   time.Time  `json:"since"`
	Allowed []string   `json:"allowed"`
	Extra   []Endpoint `json:"extra"`
}

// Isolator isolates the device with a safety net and keeps the state.
type Isolator struct {
	Backend   IsolationBackend
	StatePath string
	// Reachable checks that the server can still be reached (TCP connect).
	Reachable func(ctx context.Context) error
	// Resolve returns the addresses of a host (default: net.DefaultResolver).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// ReachTimeout bounds the check after isolating (default 30 s).
	ReachTimeout time.Duration
	Now          func() time.Time
}

func (iso *Isolator) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	if iso.Resolve != nil {
		return iso.Resolve(ctx, host)
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// AllowedAddresses resolves the server and the extra endpoints. The server
// must resolve: isolating a device the server cannot reach would strand it.
func (iso *Isolator) AllowedAddresses(ctx context.Context, serverURL string, extra []Endpoint) ([]netip.Addr, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("no server address: %q", serverURL)
	}
	server, err := iso.resolve(ctx, u.Hostname())
	if err != nil || len(server) == 0 {
		return nil, fmt.Errorf("cannot resolve the DranzoRMM server %s: %w", u.Hostname(), errors.Join(err, errors.New("no address")))
	}
	all := append([]netip.Addr{}, server...)
	for _, e := range extra {
		if ips, err := iso.resolve(ctx, e.Host); err == nil {
			all = append(all, ips...)
		}
	}
	return SortAddrs(all), nil
}

// Isolate cuts the device off, then proves the server is reachable or undoes it.
func (iso *Isolator) Isolate(ctx context.Context, serverURL string, extra []Endpoint) ([]netip.Addr, error) {
	allow, err := iso.AllowedAddresses(ctx, serverURL, extra)
	if err != nil {
		return nil, err
	}
	if err := iso.Backend.Isolate(ctx, allow); err != nil {
		return nil, err
	}
	if iso.Reachable != nil {
		timeout := iso.ReachTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		rctx, cancel := context.WithTimeout(ctx, timeout)
		rerr := iso.Reachable(rctx)
		cancel()
		if rerr != nil {
			if err := iso.Backend.Release(ctx); err != nil {
				return nil, fmt.Errorf("the server was unreachable while isolated (%w) and releasing failed: %w", rerr, err)
			}
			return nil, fmt.Errorf("the server was unreachable while isolated, so the isolation was released: %w", rerr)
		}
	}
	now := time.Now
	if iso.Now != nil {
		now = iso.Now
	}
	st := IsolationState{Active: true, Since: now().UTC(), Extra: extra}
	for _, a := range allow {
		st.Allowed = append(st.Allowed, a.String())
	}
	return allow, iso.save(&st)
}

// Release removes the isolation and the state.
func (iso *Isolator) Release(ctx context.Context) error {
	if err := iso.Backend.Release(ctx); err != nil {
		return err
	}
	if iso.StatePath != "" {
		if err := os.Remove(iso.StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// State returns the saved isolation state (nil when not isolated).
func (iso *Isolator) State() *IsolationState {
	if iso.StatePath == "" {
		return nil
	}
	b, err := fsutil.ReadFileLimited(iso.StatePath, 64<<10)
	if err != nil {
		return nil
	}
	var st IsolationState
	if json.Unmarshal(b, &st) != nil || !st.Active {
		return nil
	}
	return &st
}

// Restore re-applies a saved isolation (agent start; nftables and pf rules do
// not survive a reboot). The pinned addresses are used, so a DNS problem at
// boot cannot widen or break the isolation.
func (iso *Isolator) Restore(ctx context.Context) (bool, error) {
	st := iso.State()
	if st == nil {
		return false, nil
	}
	var allow []netip.Addr
	for _, s := range st.Allowed {
		if a, err := netip.ParseAddr(s); err == nil {
			allow = append(allow, a)
		}
	}
	if len(allow) == 0 {
		return false, errors.New("saved isolation has no allowed address")
	}
	return true, iso.Backend.Isolate(ctx, allow)
}

func (iso *Isolator) save(st *IsolationState) error {
	if iso.StatePath == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(iso.StatePath, b)
}

// ValidEndpoint checks an extra endpoint from the server.
func ValidEndpoint(e Endpoint) bool {
	if e.Port < 1 || e.Port > 65535 || len(e.Host) == 0 || len(e.Host) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(e.Host); err == nil {
		return true
	}
	for _, label := range splitDots(e.Host) {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

// HostPort formats an endpoint for logs.
func (e Endpoint) HostPort() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }
