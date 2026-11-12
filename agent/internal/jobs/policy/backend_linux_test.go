//go:build linux

package policy

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs/script"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// linuxBackend returns the real Linux backend over a recording fake
// platform, with the given tools "installed".
func linuxBackend(tools map[string]string, exit int) (*nativeBackend, *[][]string, *[]platform.Command) {
	var argv [][]string
	var cmds []platform.Command
	plat := &platform.Fake{RunFunc: func(_ context.Context, cmd platform.Command) (int, error) {
		argv = append(argv, append([]string{cmd.Path}, cmd.Args...))
		cmds = append(cmds, cmd)
		if exit != 0 && cmd.Stderr != nil {
			_, _ = io.WriteString(cmd.Stderr, "tool failed\n")
		}
		return exit, nil
	}}
	b := newBackend(plat).(*nativeBackend)
	b.look = func(names ...string) string {
		for _, n := range names {
			if p := tools[n]; p != "" {
				return p
			}
		}
		return ""
	}
	b.self = func() string { return "root" }
	return b, &argv, &cmds
}

func TestLinuxEnableFirewall(t *testing.T) {
	ctx := context.Background()

	// ufw installed: it is the one that gets enabled, even next to firewalld.
	b, argv, cmds := linuxBackend(map[string]string{"ufw": "/usr/sbin/ufw", "firewall-cmd": "/usr/bin/firewall-cmd", "systemctl": "/usr/bin/systemctl"}, 0)
	action, err := b.enableFirewall(ctx)
	if err != nil || action != "ran `ufw --force enable` (ufw denies incoming connections that have no allow rule)" || !reflect.DeepEqual(*argv, [][]string{{"/usr/sbin/ufw", "--force", "enable"}}) {
		t.Errorf("ufw: %q %v %q", action, err, *argv)
	}
	if c := (*cmds)[0]; c.AsUser != nil || c.Stdin != nil || !reflect.DeepEqual(c.Env, []string{"LC_ALL=C", "LANG=C"}) {
		t.Errorf("ufw command: %+v", c)
	}

	// Only firewalld installed.
	b, argv, _ = linuxBackend(map[string]string{"firewall-cmd": "/usr/bin/firewall-cmd", "systemctl": "/usr/bin/systemctl"}, 0)
	action, err = b.enableFirewall(ctx)
	if err != nil || action != "ran `systemctl enable --now firewalld`" || !reflect.DeepEqual(*argv, [][]string{{"/usr/bin/systemctl", "enable", "--now", "firewalld"}}) {
		t.Errorf("firewalld: %q %v %q", action, err, *argv)
	}

	// Neither installed: nothing runs and nothing is installed.
	var ro *reportOnlyError
	b, argv, _ = linuxBackend(map[string]string{"nft": "/usr/sbin/nft", "apt-get": "/usr/bin/apt-get", "dnf": "/usr/bin/dnf"}, 0)
	if _, err := b.enableFirewall(ctx); !errors.As(err, &ro) || !strings.Contains(err.Error(), "never installs software") || len(*argv) != 0 {
		t.Errorf("no firewall: %v %q", err, *argv)
	}
	// firewalld without systemd.
	b, argv, _ = linuxBackend(map[string]string{"firewall-cmd": "/usr/bin/firewall-cmd"}, 0)
	if _, err := b.enableFirewall(ctx); !errors.As(err, &ro) || len(*argv) != 0 {
		t.Errorf("no systemctl: %v %q", err, *argv)
	}
	// The tool fails.
	b, _, _ = linuxBackend(map[string]string{"ufw": "/usr/sbin/ufw"}, 1)
	if _, err := b.enableFirewall(ctx); err == nil || !strings.Contains(err.Error(), "ufw: exit code 1: tool failed") {
		t.Errorf("failure: %v", err)
	}
}

func TestLinuxRemoveAdmin(t *testing.T) {
	ctx := context.Background()
	tools := map[string]string{"gpasswd": "/usr/bin/gpasswd"}

	b, argv, cmds := linuxBackend(tools, 0)
	if err := b.removeAdmin(ctx, posture.AdminAccount{Name: "mallory", Groups: []string{"sudo", "wheel"}}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"/usr/bin/gpasswd", "-d", "mallory", "sudo"}, {"/usr/bin/gpasswd", "-d", "mallory", "wheel"}}
	if !reflect.DeepEqual(*argv, want) {
		t.Errorf("argv: %q", *argv)
	}
	for _, c := range *cmds {
		if c.AsUser != nil || c.Stdin != nil {
			t.Errorf("command: %+v", c)
		}
	}

	// Refusals: hostile names, accounts without a supplementary admin
	// group, and any group that is not an administrator group.
	b, argv, _ = linuxBackend(tools, 0)
	refused := []posture.AdminAccount{
		{Name: "bob; rm -rf /", Groups: []string{"sudo"}},
		{Name: "$(id)", Groups: []string{"sudo"}},
		{Name: "-d", Groups: []string{"sudo"}},
		{Name: "", Groups: []string{"sudo"}},
		{Name: "carol", Primary: true},
		{Name: "dave", Groups: []string{"docker"}},
		{Name: "erin", Groups: []string{"sudo; reboot"}},
	}
	for _, a := range refused {
		if err := b.removeAdmin(ctx, a); err == nil {
			t.Errorf("%+v accepted", a)
		}
	}
	if len(*argv) != 0 {
		t.Errorf("a refused removal ran a command: %q", *argv)
	}
	// userdel and friends are never part of this backend's vocabulary.
	b, argv, _ = linuxBackend(map[string]string{"gpasswd": "/usr/bin/gpasswd", "userdel": "/usr/sbin/userdel", "deluser": "/usr/sbin/deluser"}, 0)
	_ = b.removeAdmin(ctx, posture.AdminAccount{Name: "mallory", Groups: []string{"sudo"}})
	for _, a := range *argv {
		if a[0] != "/usr/bin/gpasswd" {
			t.Errorf("unexpected tool: %q", a)
		}
	}
	// gpasswd missing or failing.
	b, _, _ = linuxBackend(nil, 0)
	if err := b.removeAdmin(ctx, posture.AdminAccount{Name: "mallory", Groups: []string{"sudo"}}); err == nil {
		t.Error("no gpasswd: accepted")
	}
	b, _, _ = linuxBackend(tools, 3)
	if err := b.removeAdmin(ctx, posture.AdminAccount{Name: "mallory", Groups: []string{"sudo"}}); err == nil || !strings.Contains(err.Error(), "gpasswd: exit code 3") {
		t.Errorf("gpasswd failure: %v", err)
	}
}

func TestLinuxBackendRefusals(t *testing.T) {
	ctx := context.Background()
	b, argv, _ := linuxBackend(map[string]string{"ufw": "/usr/sbin/ufw"}, 0)
	var ro *reportOnlyError
	if _, err := b.enableDefender(ctx); !errors.As(err, &ro) || !strings.Contains(err.Error(), "fix the antivirus in that product") {
		t.Errorf("enableDefender: %v", err)
	}
	if _, err := b.setScreenLockTimeout(ctx, 300); !errors.As(err, &ro) {
		t.Errorf("setScreenLockTimeout: %v", err)
	}
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
	if len(*argv) != 0 {
		t.Errorf("commands ran: %q", *argv)
	}
	if b.accountKey("Alice") != "Alice" {
		t.Error("Linux account names are case-sensitive")
	}
}

// ---- real execution (throwaway container, root) ----

func sh(t *testing.T, line string) string {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", line).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", line, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestLinuxLivePolicy runs policy.evaluate for real: real posture collector,
// real backend, real tools. It creates and modifies local accounts, so it
// only runs when DRANZO_POLICY_LIVE=1 is set, as root, in a throwaway
// container. DRANZO_ADMIN_GROUP names the distribution's administrator
// group (sudo or wheel); DRANZO_EXPECT_UFW=1 also enables ufw for real.
func TestLinuxLivePolicy(t *testing.T) {
	if os.Getenv("DRANZO_POLICY_LIVE") != "1" {
		t.Skip("set DRANZO_POLICY_LIVE=1 (root, throwaway container only)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	group := os.Getenv("DRANZO_ADMIN_GROUP")
	if group != "sudo" && group != "wheel" {
		t.Fatal("DRANZO_ADMIN_GROUP must be sudo or wheel")
	}
	for _, u := range []string{"dzkeep", "dzextra1", "dzextra2"} {
		sh(t, "useradd -m "+u)
		sh(t, "usermod -aG "+group+" "+u)
	}
	inGroup := func(user string) bool {
		for _, g := range strings.Fields(sh(t, "id -nG "+user)) {
			if g == group {
				return true
			}
		}
		return false
	}

	plat := platform.New()
	r := newRig(t)
	r.h = &Handler{src: posture.New(plat, nil), be: newBackend(plat), script: script.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	eval := func(checks ...protocol.PolicyCheck) []protocol.PolicyCheckResult {
		t.Helper()
		jc := r.jobContext(ctx, protocol.PolicyEvaluateSpec{Checks: checks})
		jc.Platform = plat
		res := r.h.Handle(jc)
		if res.Status != protocol.StatusSucceeded {
			t.Fatalf("job: %s %s", res.Status, res.Message)
		}
		out := res.Result.(protocol.PolicyEvaluateResult).Results
		for _, o := range out {
			t.Logf("%s: compliant=%v remediated=%v detail=%s", o.Check, o.Compliant, o.Remediated, o.Detail)
		}
		return out
	}
	allowed := map[string]any{"allowed": []any{"dzkeep"}}

	// Report only: both extras are found, nothing changes.
	got := eval(protocol.PolicyCheck{PolicyID: "admins", Check: CheckLocalAdmins, Params: allowed})[0]
	expect(t, got, false, false, "unexpected administrators: dzextra1, dzextra2")
	if !inGroup("dzextra1") || !inGroup("dzextra2") {
		t.Fatal("changed without remediate")
	}

	// Remediation: both leave the group; the accounts and their homes stay.
	got = eval(protocol.PolicyCheck{PolicyID: "admins", Check: CheckLocalAdmins, Params: allowed, Remediate: true})[0]
	expect(t, got, true, true, "removed from the administrators group (accounts not deleted): dzextra1, dzextra2")
	for _, u := range []string{"dzextra1", "dzextra2"} {
		if inGroup(u) {
			t.Errorf("%s is still in %s", u, group)
		}
		if out := sh(t, "getent passwd "+u); !strings.HasPrefix(out, u+":") {
			t.Errorf("account %s is gone: %q", u, out)
		}
		if _, err := os.Stat("/home/" + u); err != nil {
			t.Errorf("home of %s is gone: %v", u, err)
		}
	}
	if !inGroup("dzkeep") {
		t.Error("the allowed administrator was removed")
	}
	if !strings.HasPrefix(sh(t, "getent passwd root"), "root:x:0:0:") {
		t.Error("root was changed")
	}
	if logs := r.remediationLogs(); len(logs) != 1 || !strings.Contains(logs[0]["before"].(string), "dzextra1") || strings.Contains(logs[0]["after"].(string), "dzextra1") {
		t.Errorf("remediation log: %v", logs)
	}
	// Compliant now.
	expect(t, eval(protocol.PolicyCheck{PolicyID: "admins", Check: CheckLocalAdmins, Params: allowed, Remediate: true})[0], true, false)

	// The last remaining administrator is not removed, even when not allowed.
	got = eval(protocol.PolicyCheck{PolicyID: "admins", Check: CheckLocalAdmins, Params: map[string]any{"allowed": []any{}}, Remediate: true})[0]
	expect(t, got, false, false, "kept: dzkeep (last remaining administrator)")
	if !inGroup("dzkeep") {
		t.Error("the last administrator was removed")
	}

	// A script check with remediation, run by the real script handler.
	marker := t.TempDir() + "/marker"
	got = eval(protocol.PolicyCheck{PolicyID: "script", Check: CheckScript, Remediate: true, Params: map[string]any{
		"language": "sh", "checkScript": "test -f '" + marker + "'", "remediationScript": "id -u > '" + marker + "'",
	}})[0]
	expect(t, got, true, true, "re-check exit code 0")
	if data, _ := os.ReadFile(marker); strings.TrimSpace(string(data)) != "0" {
		t.Errorf("the remediation script did not run as root: %q", data)
	}

	// Checks this OS cannot do, and a report-only one.
	results := eval(
		protocol.PolicyCheck{PolicyID: "usb", Check: CheckUSBStorage, Remediate: true},
		protocol.PolicyCheck{PolicyID: "pw", Check: CheckPasswordPolicy, Params: map[string]any{"minLength": 12.0}, Remediate: true},
		protocol.PolicyCheck{PolicyID: "enc", Check: CheckDiskEncryption, Remediate: true},
		protocol.PolicyCheck{PolicyID: "av", Check: CheckAntivirus, Remediate: true},
		protocol.PolicyCheck{PolicyID: "lock", Check: CheckScreenLock, Params: map[string]any{"maxSeconds": 600.0}, Remediate: true},
	)
	for i, prefix := range []string{
		"not supported on this OS: usb.storage.blocked is available on Windows only",
		"not supported on this OS: password.policy is available on Windows only",
		"not supported on this OS: the root file system is not on a block device", // container
		"no enabled antivirus (no antivirus product found); not remediated: no antivirus product is installed and the agent never installs software",
		"not supported on this OS: no ", // no GNOME desktop, or nobody logged in at the console
	} {
		if !strings.HasPrefix(results[i].Detail, prefix) || results[i].Compliant || results[i].Remediated {
			t.Errorf("result %d: %+v", i, results[i])
		}
	}

	// The firewall.
	fw := protocol.PolicyCheck{PolicyID: "fw", Check: CheckFirewall}
	if os.Getenv("DRANZO_EXPECT_UFW") == "1" {
		expect(t, eval(fw)[0], false, false, "firewall is off", "ufw: inactive")
		fw.Remediate = true
		expect(t, eval(fw)[0], true, true, "ran `ufw --force enable`", "ufw: active")
		if out := sh(t, "ufw status"); !strings.HasPrefix(out, "Status: active") {
			t.Errorf("ufw status: %s", out)
		}
		expect(t, eval(fw)[0], true, false, "firewall is on")
		return
	}
	// No ufw / firewalld installed: reported, never installed.
	fw.Remediate = true
	got = eval(fw)[0]
	if got.Compliant || got.Remediated {
		t.Errorf("firewall: %+v", got)
	}
	if posture.LookTool("ufw", "firewall-cmd") != "" {
		t.Error("a firewall was installed")
	}
}
