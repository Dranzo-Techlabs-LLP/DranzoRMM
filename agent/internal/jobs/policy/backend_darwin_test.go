//go:build darwin

package policy

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs/script"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// fakeMac simulates the macOS tools the firewall and admin checks use.
type fakeMac struct {
	mu         sync.Mutex
	firewallOn bool
	admins     []string
	calls      [][]string
	failWrites bool
}

func (m *fakeMac) run(_ context.Context, cmd platform.Command) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	argv := append([]string{cmd.Path}, cmd.Args...)
	m.calls = append(m.calls, argv)
	if cmd.AsUser != nil || cmd.Stdin != nil {
		return platform.ExitCodeUnknown, errors.New("unexpected AsUser / stdin")
	}
	switch strings.Join(argv, " ") {
	case "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate":
		if m.firewallOn {
			_, _ = io.WriteString(cmd.Stdout, "Firewall is enabled. (State = 1)\n")
		} else {
			_, _ = io.WriteString(cmd.Stdout, "Firewall is disabled. (State = 0)\n")
		}
		return 0, nil
	case "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on":
		if m.failWrites {
			_, _ = io.WriteString(cmd.Stderr, "Must be root to change settings.\n")
			return 255, nil
		}
		m.firewallOn = true
		return 0, nil
	case "/usr/bin/dscl . -read /Groups/admin GroupMembership":
		_, _ = io.WriteString(cmd.Stdout, "GroupMembership: "+strings.Join(m.admins, " ")+"\n")
		return 0, nil
	}
	if len(argv) == 8 && strings.Join(argv[:4], " ") == "/usr/sbin/dseditgroup -o edit -d" && strings.Join(argv[5:], " ") == "-t user admin" {
		if m.failWrites {
			_, _ = io.WriteString(cmd.Stderr, "Operation failed with error: Permission denied\n")
			return 77, nil
		}
		var left []string
		for _, a := range m.admins {
			if a != argv[4] {
				left = append(left, a)
			}
		}
		m.admins = left
		return 0, nil
	}
	return platform.ExitCodeUnknown, errors.New("unexpected command: " + strings.Join(argv, " "))
}

// writes returns the commands that change something.
func (m *fakeMac) writes() [][]string {
	var out [][]string
	for _, c := range m.calls {
		if strings.Contains(strings.Join(c, " "), "--setglobalstate") || c[0] == "/usr/sbin/dseditgroup" {
			out = append(out, c)
		}
	}
	return out
}

// macRig wires the real posture collector and the real macOS backend to the
// simulated tools: the whole check -> remediate -> re-check path with the
// exact argv.
func macRig(t *testing.T, m *fakeMac) *rig {
	t.Helper()
	plat := &platform.Fake{RunFunc: m.run}
	r := newRig(t)
	be := newBackend(plat).(*nativeBackend)
	be.self = func() string { return "root" }
	r.h = &Handler{src: posture.New(plat, nil), be: be, script: script.New()}
	return r
}

func TestDarwinFirewallRemediation(t *testing.T) {
	m := &fakeMac{}
	r := macRig(t, m)
	expect(t, r.one(CheckFirewall, nil, false), false, false, "firewall is off (Application Firewall: off (state 0))")
	if len(m.writes()) != 0 {
		t.Fatalf("changed without remediate: %v", m.writes())
	}
	expect(t, r.one(CheckFirewall, nil, true), true, true, "ran `socketfilterfw --setglobalstate on`", "firewall is on (Application Firewall: on (state 1))")
	want := [][]string{{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"}}
	if !reflect.DeepEqual(m.writes(), want) {
		t.Errorf("argv: %q", m.writes())
	}
	// Compliant now: nothing more is written.
	expect(t, r.one(CheckFirewall, nil, true), true, false)
	if len(m.writes()) != 1 {
		t.Errorf("argv: %q", m.writes())
	}
	// Not root: the tool refuses, the result says so.
	m = &fakeMac{failWrites: true}
	r = macRig(t, m)
	expect(t, r.one(CheckFirewall, nil, true), false, false, "remediation failed: socketfilterfw: exit code 255: Must be root to change settings.")
}

func TestDarwinLocalAdminsRemediation(t *testing.T) {
	m := &fakeMac{admins: []string{"root", "alice", "mallory", "eve"}}
	r := macRig(t, m)
	allowed := map[string]any{"allowed": []any{"Alice"}} // macOS names compare case-insensitively
	expect(t, r.one(CheckLocalAdmins, allowed, false), false, false, "unexpected administrators: eve, mallory")
	if len(m.writes()) != 0 {
		t.Fatalf("changed without remediate: %v", m.writes())
	}
	expect(t, r.one(CheckLocalAdmins, allowed, true), true, true, "removed from the administrators group (accounts not deleted): eve, mallory")
	want := [][]string{
		{"/usr/sbin/dseditgroup", "-o", "edit", "-d", "eve", "-t", "user", "admin"},
		{"/usr/sbin/dseditgroup", "-o", "edit", "-d", "mallory", "-t", "user", "admin"},
	}
	if !reflect.DeepEqual(m.writes(), want) {
		t.Errorf("argv: %q", m.writes())
	}
	if !reflect.DeepEqual(m.admins, []string{"root", "alice"}) {
		t.Errorf("admins: %v", m.admins)
	}

	// root is never removed; the last administrator stays.
	m = &fakeMac{admins: []string{"root", "bob"}}
	r = macRig(t, m)
	expect(t, r.one(CheckLocalAdmins, map[string]any{"allowed": []any{}}, true), false, false, "kept: bob (last remaining administrator)")
	if len(m.writes()) != 0 {
		t.Errorf("argv: %q", m.writes())
	}
	// The account the agent runs as is never removed.
	m = &fakeMac{admins: []string{"root", "alice", "agentsvc"}}
	r = macRig(t, m)
	r.h.be.(*nativeBackend).self = func() string { return "AgentSvc" }
	expect(t, r.one(CheckLocalAdmins, map[string]any{"allowed": []any{"alice"}}, true), false, false, "kept: agentsvc (the account the agent runs as)")
	if len(m.writes()) != 0 {
		t.Errorf("argv: %q", m.writes())
	}
}

func TestDarwinBackendRefusals(t *testing.T) {
	ctx := context.Background()
	var calls int
	plat := &platform.Fake{RunFunc: func(context.Context, platform.Command) (int, error) { calls++; return 0, nil }}
	b := newBackend(plat).(*nativeBackend)

	// Hostile or odd names never become an argument.
	for _, name := range []string{"bob; rm -rf /", "$(id)", "-o", "", "bob\nroot", "a/b"} {
		if err := b.removeAdmin(ctx, posture.AdminAccount{Name: name, Groups: []string{"admin"}}); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	// The only antivirus fix belongs to Windows; nothing runs here.
	var ro *reportOnlyError
	if _, err := b.enableDefender(ctx); !errors.As(err, &ro) || !strings.Contains(err.Error(), "fix the antivirus in that product") {
		t.Errorf("enableDefender: %v", err)
	}
	if _, err := b.setScreenLockTimeout(ctx, 300); !errors.As(err, &ro) || !strings.Contains(err.Error(), "MDM") {
		t.Errorf("setScreenLockTimeout: %v", err)
	}
	// Windows-only checks are unsupported.
	var ue *posture.UnsupportedError
	if _, _, err := b.usbStorage(ctx); !errors.As(err, &ue) {
		t.Errorf("usbStorage: %v", err)
	}
	if _, err := b.blockUSBStorage(ctx); !errors.As(err, &ue) {
		t.Errorf("blockUSBStorage: %v", err)
	}
	if _, err := b.passwordPolicy(ctx); !errors.As(err, &ue) {
		t.Errorf("passwordPolicy: %v", err)
	}
	if _, err := b.setPasswordPolicy(ctx, nil, nil); !errors.As(err, &ue) {
		t.Errorf("setPasswordPolicy: %v", err)
	}
	if calls != 0 {
		t.Errorf("%d commands ran", calls)
	}
	if b.accountKey("Alice") != "alice" {
		t.Error("accountKey")
	}

	// Through the handler: the Windows-only checks and an antivirus that is
	// not Defender, with remediation requested.
	m := &fakeMac{}
	r := macRig(t, m)
	results := r.run(
		protocol.PolicyCheck{PolicyID: "u", Check: CheckUSBStorage, Remediate: true},
		protocol.PolicyCheck{PolicyID: "p", Check: CheckPasswordPolicy, Params: map[string]any{"minLength": 12.0}, Remediate: true},
	)
	if results[0].Detail != "not supported on this OS: usb.storage.blocked is available on Windows only" ||
		results[1].Detail != "not supported on this OS: password.policy is available on Windows only" {
		t.Errorf("%+v", results)
	}
	for _, res := range results {
		if res.Compliant || res.Remediated {
			t.Errorf("%+v", res)
		}
	}
	if len(m.calls) != 0 {
		t.Errorf("commands ran: %v", m.calls)
	}
}
