package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/script"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// fakeSource is the state of an imaginary device.
type fakeSource struct {
	av        []protocol.AntivirusProduct
	avErr     error
	fw        *protocol.FirewallState
	fwErr     error
	enc       []protocol.DiskEncryption
	encErr    error
	admins    []posture.AdminAccount
	adminsErr error
	lock      *protocol.ScreenLock
	lockErr   error
}

func (s *fakeSource) Antivirus(context.Context) ([]protocol.AntivirusProduct, error) {
	return append([]protocol.AntivirusProduct(nil), s.av...), s.avErr
}

func (s *fakeSource) Firewall(context.Context) (*protocol.FirewallState, error) {
	if s.fwErr != nil {
		return nil, s.fwErr
	}
	fw := *s.fw
	return &fw, nil
}

func (s *fakeSource) DiskEncryption(context.Context) ([]protocol.DiskEncryption, error) {
	return s.enc, s.encErr
}

func (s *fakeSource) LocalAdminAccounts(context.Context) ([]posture.AdminAccount, error) {
	return append([]posture.AdminAccount(nil), s.admins...), s.adminsErr
}

func (s *fakeSource) ScreenLock(context.Context) (*protocol.ScreenLock, error) {
	if s.lockErr != nil {
		return nil, s.lockErr
	}
	l := *s.lock
	return &l, nil
}

// fakeBackend applies remediations to the fakeSource and records every call.
type fakeBackend struct {
	src   *fakeSource
	calls []string
	// failing makes a remediation return this error; ineffective makes it
	// report success without changing anything (a policy overrides it).
	failing     map[string]error
	ineffective map[string]bool
	self        string
	foldCase    bool

	usbBlocked bool
	usbErr     error
	password   PasswordPolicy
	passErr    error
}

func (b *fakeBackend) do(name string, apply func()) (string, error) {
	b.calls = append(b.calls, name)
	if err := b.failing[strings.Fields(name)[0]]; err != nil {
		return "", err
	}
	if !b.ineffective[strings.Fields(name)[0]] {
		apply()
	}
	return "did " + name, nil
}

func (b *fakeBackend) enableFirewall(context.Context) (string, error) {
	return b.do("enableFirewall", func() { b.src.fw = &protocol.FirewallState{Enabled: true, Detail: "fake: on"} })
}

func (b *fakeBackend) enableDefender(context.Context) (string, error) {
	return b.do("enableDefender", func() {
		for i := range b.src.av {
			if posture.IsDefenderName(b.src.av[i].Name) {
				b.src.av[i].Enabled = true
			}
		}
	})
}

func (b *fakeBackend) setScreenLockTimeout(_ context.Context, seconds int) (string, error) {
	return b.do(fmt.Sprintf("setScreenLockTimeout %d", seconds), func() {
		b.src.lock = &protocol.ScreenLock{Enabled: true, TimeoutSeconds: seconds}
	})
}

func (b *fakeBackend) removeAdmin(_ context.Context, a posture.AdminAccount) error {
	_, err := b.do("removeAdmin "+a.Name, func() {
		var left []posture.AdminAccount
		for _, x := range b.src.admins {
			if x.Name != a.Name {
				left = append(left, x)
			}
		}
		b.src.admins = left
	})
	return err
}

func (b *fakeBackend) selfAccount() string { return b.self }

func (b *fakeBackend) accountKey(name string) string {
	if b.foldCase {
		return strings.ToLower(name)
	}
	return name
}

func (b *fakeBackend) usbStorage(context.Context) (bool, string, error) {
	if b.usbErr != nil {
		return false, "", b.usbErr
	}
	if b.usbBlocked {
		return true, "USBSTOR Start=4", nil
	}
	return false, "USBSTOR Start=3", nil
}

func (b *fakeBackend) blockUSBStorage(context.Context) (string, error) {
	return b.do("blockUSBStorage", func() { b.usbBlocked = true })
}

func (b *fakeBackend) passwordPolicy(context.Context) (PasswordPolicy, error) {
	return b.password, b.passErr
}

func (b *fakeBackend) setPasswordPolicy(_ context.Context, minLength, maxAgeDays *int) (string, error) {
	return b.do("setPasswordPolicy "+strings.Join(netAccountsArgs(minLength, maxAgeDays)[1:], " "), func() {
		if minLength != nil {
			b.password.MinLength = *minLength
		}
		if maxAgeDays != nil {
			b.password.MaxAgeDays = *maxAgeDays
		}
	})
}

// rig is one test set-up: a handler over the fakes and a captured log.
type rig struct {
	t   *testing.T
	src *fakeSource
	be  *fakeBackend
	h   *Handler
	log bytes.Buffer
	out bytes.Buffer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, src: &fakeSource{
		fw:   &protocol.FirewallState{Enabled: true, Detail: "fake: on"},
		lock: &protocol.ScreenLock{Enabled: true, TimeoutSeconds: 300},
	}}
	r.be = &fakeBackend{src: r.src, failing: map[string]error{}, ineffective: map[string]bool{}, self: "SYSTEM"}
	r.h = &Handler{src: r.src, be: r.be, script: script.New()}
	return r
}

func (r *rig) jobContext(ctx context.Context, spec any) *jobs.JobContext {
	raw, err := json.Marshal(spec)
	if err != nil {
		r.t.Fatal(err)
	}
	return &jobs.JobContext{
		Ctx:      ctx,
		DeviceID: "11111111-1111-4111-8111-111111111111",
		JobRunID: "22222222-2222-4222-8222-222222222222",
		Kind:     protocol.KindPolicyEvaluate,
		Spec:     raw,
		Stdout:   &r.out,
		Stderr:   &r.out,
		Log:      slog.New(slog.NewJSONHandler(&r.log, nil)),
		Platform: &platform.Fake{},
		TempDir:  r.t.TempDir(),
	}
}

// run evaluates the checks and returns the per-check results.
func (r *rig) run(checks ...protocol.PolicyCheck) []protocol.PolicyCheckResult {
	r.t.Helper()
	res := r.h.Handle(r.jobContext(context.Background(), protocol.PolicyEvaluateSpec{Checks: checks}))
	if res.Status != protocol.StatusSucceeded {
		r.t.Fatalf("job status %s: %s", res.Status, res.Message)
	}
	out, ok := res.Result.(protocol.PolicyEvaluateResult)
	if !ok {
		r.t.Fatalf("result type %T", res.Result)
	}
	if len(out.Results) != len(checks) {
		r.t.Fatalf("%d results for %d checks", len(out.Results), len(checks))
	}
	for i, c := range checks {
		if out.Results[i].PolicyID != c.PolicyID || out.Results[i].Check != c.Check {
			r.t.Errorf("result %d does not echo the check: %+v", i, out.Results[i])
		}
	}
	return out.Results
}

// one evaluates a single check.
func (r *rig) one(check string, params map[string]any, remediate bool) protocol.PolicyCheckResult {
	r.t.Helper()
	return r.run(protocol.PolicyCheck{PolicyID: "pol-1", Check: check, Params: params, Remediate: remediate})[0]
}

// remediationLogs returns the structured "policy remediation" log lines.
func (r *rig) remediationLogs() []map[string]any {
	var lines []map[string]any
	for _, line := range strings.Split(r.log.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "policy remediation" {
			lines = append(lines, m)
		}
	}
	return lines
}

func expect(t *testing.T, got protocol.PolicyCheckResult, compliant, remediated bool, detailParts ...string) {
	t.Helper()
	if got.Compliant != compliant || got.Remediated != remediated {
		t.Errorf("compliant=%v remediated=%v, want %v %v (detail: %s)", got.Compliant, got.Remediated, compliant, remediated, got.Detail)
	}
	for _, part := range detailParts {
		if !strings.Contains(got.Detail, part) {
			t.Errorf("detail %q lacks %q", got.Detail, part)
		}
	}
}

// ---- firewall.enabled ----

func TestFirewallCheck(t *testing.T) {
	r := newRig(t)
	expect(t, r.one(CheckFirewall, nil, true), true, false, "firewall is on")
	if len(r.be.calls) != 0 {
		t.Errorf("a compliant device was touched: %v", r.be.calls)
	}

	// Not compliant, no remediation requested: nothing is changed.
	r = newRig(t)
	r.src.fw = &protocol.FirewallState{Enabled: false, Detail: "ufw: inactive"}
	expect(t, r.one(CheckFirewall, nil, false), false, false, "firewall is off (ufw: inactive)")
	if len(r.be.calls) != 0 || len(r.remediationLogs()) != 0 {
		t.Errorf("changed without remediate: %v", r.be.calls)
	}

	// Remediation: one call, re-check, one log line with before and after.
	expect(t, r.one(CheckFirewall, nil, true), true, true, "was off", "did enableFirewall", "firewall is on")
	if !reflect.DeepEqual(r.be.calls, []string{"enableFirewall"}) {
		t.Errorf("calls: %v", r.be.calls)
	}
	logs := r.remediationLogs()
	if len(logs) != 1 || logs[0]["check"] != CheckFirewall || logs[0]["policy_id"] != "pol-1" ||
		logs[0]["action"] != "did enableFirewall" || logs[0]["before"] != "firewall is off (ufw: inactive)" ||
		logs[0]["after"] != "firewall is on (fake: on)" || logs[0]["compliant_after"] != true {
		t.Errorf("remediation log: %v", logs)
	}

	// The fix ran but a policy keeps the firewall off: not remediated.
	r = newRig(t)
	r.src.fw = &protocol.FirewallState{Enabled: false, Detail: "off by GPO"}
	r.be.ineffective["enableFirewall"] = true
	expect(t, r.one(CheckFirewall, nil, true), false, false, "firewall is still off")

	// The fix failed, or does not exist on this device.
	r = newRig(t)
	r.src.fw = &protocol.FirewallState{Enabled: false, Detail: "off"}
	r.be.failing["enableFirewall"] = errors.New("ufw: exit code 1: boom")
	expect(t, r.one(CheckFirewall, nil, true), false, false, "remediation failed: ufw: exit code 1: boom")
	if logs := r.remediationLogs(); len(logs) != 1 || logs[0]["level"] != "WARN" || logs[0]["error"] != "ufw: exit code 1: boom" {
		t.Errorf("failure log: %v", logs)
	}
	r.be.failing["enableFirewall"] = reportOnlyf("neither ufw nor firewalld is installed and the agent never installs software")
	got := r.one(CheckFirewall, nil, true)
	expect(t, got, false, false, "not remediated: neither ufw nor firewalld is installed")
	if strings.HasPrefix(got.Detail, DetailUnsupportedPrefix) {
		t.Errorf("a missing fix must not read as an unsupported check: %s", got.Detail)
	}

	// The state cannot be read on this device.
	r = newRig(t)
	r.src.fwErr = posture.Unsupportedf("the firewall state cannot be determined (nftables: not readable)")
	got = r.one(CheckFirewall, nil, true)
	expect(t, got, false, false)
	if got.Detail != "not supported on this OS: the firewall state cannot be determined (nftables: not readable)" {
		t.Errorf("detail %q", got.Detail)
	}
	r.src.fwErr = errors.New("powershell: exit code 1")
	expect(t, r.one(CheckFirewall, nil, true), false, false, "check failed: powershell: exit code 1")
	if len(r.be.calls) != 0 {
		t.Errorf("remediated without knowing the state: %v", r.be.calls)
	}
}

// ---- antivirus.enabled ----

func TestAntivirusCheck(t *testing.T) {
	defenderOff := protocol.AntivirusProduct{Name: "Windows Defender", Enabled: false, UpToDate: true, SignatureVersion: "1.421.612.0", Source: "wsc"}
	defenderOn := defenderOff
	defenderOn.Enabled = true

	r := newRig(t)
	r.src.av = []protocol.AntivirusProduct{defenderOn}
	expect(t, r.one(CheckAntivirus, nil, true), true, false, "Windows Defender: enabled, up to date, signatures 1.421.612.0")

	// Defender off, no remediation.
	r = newRig(t)
	r.src.av = []protocol.AntivirusProduct{defenderOff}
	expect(t, r.one(CheckAntivirus, nil, false), false, false, "no enabled antivirus", "Windows Defender: disabled")
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}

	// Defender off, remediation: the one permitted fix.
	expect(t, r.one(CheckAntivirus, nil, true), true, true, "was disabled", "did enableDefender", "Windows Defender: enabled")
	if !reflect.DeepEqual(r.be.calls, []string{"enableDefender"}) {
		t.Errorf("calls: %v", r.be.calls)
	}
	if logs := r.remediationLogs(); len(logs) != 1 || logs[0]["action"] != "did enableDefender" ||
		!strings.Contains(fmt.Sprint(logs[0]["before"]), "disabled") || !strings.Contains(fmt.Sprint(logs[0]["after"]), "enabled") {
		t.Errorf("log: %v", logs)
	}

	// Tamper protection: the cmdlet succeeds but nothing changes.
	r = newRig(t)
	r.src.av = []protocol.AntivirusProduct{defenderOff}
	r.be.ineffective["enableDefender"] = true
	expect(t, r.one(CheckAntivirus, nil, true), false, false, "still disabled", "tamper protection")
}

// TestAntivirusGuardRails: the agent refuses every antivirus remediation
// except re-enabling Microsoft Defender as reported by Windows itself.
func TestAntivirusGuardRails(t *testing.T) {
	cases := []struct {
		name     string
		products []protocol.AntivirusProduct
		detail   string
	}{
		{"third-party product off", []protocol.AntivirusProduct{
			{Name: "Sophos Anti-Virus", Source: "wsc"},
		}, "Sophos Anti-Virus must be fixed in that product"},
		{"third-party next to Defender", []protocol.AntivirusProduct{
			{Name: "Windows Defender", Source: "wsc"},
			{Name: "ESET Security", Source: "wsc"},
		}, "ESET Security must be fixed in that product"},
		{"Defender for Endpoint on macOS / Linux", []protocol.AntivirusProduct{
			{Name: "Microsoft Defender for Endpoint", Source: "known_av"},
		}, "Microsoft Defender for Endpoint must be fixed in that product"},
		{"ClamAV stopped", []protocol.AntivirusProduct{
			{Name: "ClamAV", Source: "clamav"},
		}, "ClamAV must be fixed in that product"},
		{"nothing installed", nil, "the agent never installs software"},
		{"only the Gatekeeper entry", []protocol.AntivirusProduct{
			{Name: "Gatekeeper", Enabled: true, UpToDate: true, Source: "xprotect"},
		}, "the agent never installs software"},
	}
	for _, c := range cases {
		r := newRig(t)
		r.src.av = c.products
		got := r.one(CheckAntivirus, nil, true)
		expect(t, got, false, false, "not remediated", c.detail)
		if len(r.be.calls) != 0 {
			t.Errorf("%s: the backend was called: %v", c.name, r.be.calls)
		}
		if ok, _ := defenderRemediable(c.products); ok {
			t.Errorf("%s: judged remediable", c.name)
		}
	}
	// Gatekeeper being on does not make a Mac without XProtect compliant,
	// and XProtect alone does.
	r := newRig(t)
	r.src.av = []protocol.AntivirusProduct{
		{Name: "XProtect", Enabled: true, UpToDate: true, SignatureVersion: "5372", Source: "xprotect"},
		{Name: "Gatekeeper", Enabled: false, UpToDate: true, Source: "xprotect"},
	}
	expect(t, r.one(CheckAntivirus, nil, true), true, false, "XProtect: enabled", "Gatekeeper: disabled")

	// The remediation script itself only switches protection on.
	low := strings.ToLower(PSEnableDefender)
	for _, bad := range []string{"$true", "uninstall", "remove-", "stop-service", "disable-", "add-mppreference", "exclusion", "set-service", "sc.exe", "reg ", "-disablebehaviormonitoring", "-disableioavprotection"} {
		if strings.Contains(low, bad) {
			t.Errorf("PSEnableDefender contains %q", bad)
		}
	}
	if strings.Count(low, "set-mppreference") != 1 || !strings.Contains(PSEnableDefender, "Set-MpPreference -DisableRealtimeMonitoring $false") {
		t.Errorf("PSEnableDefender is not the supported re-enable call: %s", PSEnableDefender)
	}
	// The antivirus state cannot be read.
	r = newRig(t)
	r.src.avErr = posture.Unsupportedf("neither Windows Security Center nor Microsoft Defender status is available")
	got := r.one(CheckAntivirus, nil, true)
	if !strings.HasPrefix(got.Detail, DetailUnsupportedPrefix) || got.Compliant || got.Remediated || len(r.be.calls) != 0 {
		t.Errorf("%+v %v", got, r.be.calls)
	}
}

// ---- screenlock.timeout ----

func TestScreenLockCheck(t *testing.T) {
	r := newRig(t)
	expect(t, r.one(CheckScreenLock, map[string]any{"maxSeconds": 600.0}, true), true, false, "screen locks after 300 seconds")
	expect(t, r.one(CheckScreenLock, map[string]any{"maxSeconds": 300.0}, true), true, false)
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}
	// Too long, report only.
	expect(t, r.one(CheckScreenLock, map[string]any{"maxSeconds": 120.0}, false), false, false, "screen locks after 300 seconds (required: at most 120)")
	// Too long, remediated with exactly the requested value.
	expect(t, r.one(CheckScreenLock, map[string]any{"maxSeconds": 120.0}, true), true, true, "did setScreenLockTimeout 120", "screen locks after 120 seconds")
	if !reflect.DeepEqual(r.be.calls, []string{"setScreenLockTimeout 120"}) {
		t.Errorf("calls: %v", r.be.calls)
	}
	if logs := r.remediationLogs(); len(logs) != 1 || !strings.Contains(fmt.Sprint(logs[0]["before"]), "300 seconds") || logs[0]["after"] != "screen locks after 120 seconds" {
		t.Errorf("log: %v", logs)
	}

	// No lock at all; macOS / Linux have no machine-wide setting.
	r = newRig(t)
	r.src.lock = &protocol.ScreenLock{}
	r.be.failing["setScreenLockTimeout"] = reportOnlyf("report only on macOS: a machine-wide screen lock needs an MDM configuration profile")
	got := r.one(CheckScreenLock, map[string]any{"maxSeconds": 600.0}, true)
	expect(t, got, false, false, "no automatic screen lock", "not remediated: report only on macOS")
	if strings.HasPrefix(got.Detail, DetailUnsupportedPrefix) {
		t.Errorf("detail %q", got.Detail)
	}
	// Nobody logged in.
	r.src.lockErr = posture.Unsupportedf("no user is logged in (the screen lock is a per-user setting)")
	got = r.one(CheckScreenLock, map[string]any{"maxSeconds": 600.0}, true)
	if got.Detail != "not supported on this OS: no user is logged in (the screen lock is a per-user setting)" {
		t.Errorf("detail %q", got.Detail)
	}

	// Parameter validation: nothing is read or changed.
	r = newRig(t)
	bad := []map[string]any{
		nil, {}, {"maxSeconds": "300"}, {"maxSeconds": 0.0}, {"maxSeconds": -5.0}, {"maxSeconds": 86401.0},
		{"maxSeconds": 12.5}, {"maxSeconds": true}, {"maxSeconds": []any{300.0}}, {"maxSeconds": 1e30},
	}
	for _, params := range bad {
		got := r.one(CheckScreenLock, params, true)
		if !strings.HasPrefix(got.Detail, DetailInvalidPrefix) || got.Compliant || got.Remediated {
			t.Errorf("%v: %+v", params, got)
		}
	}
	if len(r.be.calls) != 0 {
		t.Errorf("calls with invalid params: %v", r.be.calls)
	}
}

// ---- usb.storage.blocked, password.policy, diskencryption.enabled ----

func TestUSBStorageCheck(t *testing.T) {
	r := newRig(t)
	r.be.usbBlocked = true
	expect(t, r.one(CheckUSBStorage, nil, true), true, false, "USB mass storage is blocked (USBSTOR Start=4)")

	r = newRig(t)
	expect(t, r.one(CheckUSBStorage, nil, false), false, false, "USB mass storage is not blocked (USBSTOR Start=3)")
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}
	expect(t, r.one(CheckUSBStorage, nil, true), true, true, "did blockUSBStorage", "already connected")
	if !reflect.DeepEqual(r.be.calls, []string{"blockUSBStorage"}) || len(r.remediationLogs()) != 1 {
		t.Errorf("calls: %v logs: %v", r.be.calls, r.remediationLogs())
	}

	// Not Windows.
	r = newRig(t)
	r.be.usbErr = posture.Unsupportedf("usb.storage.blocked is available on Windows only")
	got := r.one(CheckUSBStorage, nil, true)
	if got.Detail != "not supported on this OS: usb.storage.blocked is available on Windows only" || got.Compliant || got.Remediated || len(r.be.calls) != 0 {
		t.Errorf("%+v %v", got, r.be.calls)
	}
}

func TestPasswordPolicyCheck(t *testing.T) {
	on, off := true, false
	r := newRig(t)
	r.be.password = PasswordPolicy{MinLength: 12, MaxAgeDays: 60, Complexity: &on}
	want := map[string]any{"minLength": 12.0, "maxAgeDays": 90.0, "complexity": true}
	expect(t, r.one(CheckPasswordPolicy, want, true), true, false, "minimum length 12, maximum age 60 days, complexity on")

	// Too short and never expiring, report only.
	r = newRig(t)
	r.be.password = PasswordPolicy{MinLength: 0, MaxAgeDays: 0, Complexity: &on}
	expect(t, r.one(CheckPasswordPolicy, want, false), false, false, "minimum length is 0, required 12", "passwords never expire, required at most 90 days")
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}
	// Remediated with exactly the two values.
	expect(t, r.one(CheckPasswordPolicy, want, true), true, true, "did setPasswordPolicy /minpwlen:12 /maxpwage:90", "minimum length 12, maximum age 90 days")
	if !reflect.DeepEqual(r.be.calls, []string{"setPasswordPolicy /minpwlen:12 /maxpwage:90"}) {
		t.Errorf("calls: %v", r.be.calls)
	}

	// Only the failing value is set, and a stricter current value is never loosened.
	r = newRig(t)
	r.be.password = PasswordPolicy{MinLength: 14, MaxAgeDays: 365, Complexity: &on}
	expect(t, r.one(CheckPasswordPolicy, want, true), true, true)
	if !reflect.DeepEqual(r.be.calls, []string{"setPasswordPolicy /maxpwage:90"}) || r.be.password.MinLength != 14 {
		t.Errorf("calls: %v policy: %+v", r.be.calls, r.be.password)
	}

	// Complexity is report only: with nothing else to fix nothing is called.
	r = newRig(t)
	r.be.password = PasswordPolicy{MinLength: 12, MaxAgeDays: 60, Complexity: &off}
	expect(t, r.one(CheckPasswordPolicy, want, true), false, false, "complexity requirement is off", "not remediated", "report only")
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}
	// Length fixed, complexity still off: not compliant, not "remediated".
	r.be.password = PasswordPolicy{MinLength: 6, MaxAgeDays: 60, Complexity: nil}
	expect(t, r.one(CheckPasswordPolicy, want, true), false, false, "did setPasswordPolicy /minpwlen:12", "still not compliant: complexity requirement could not be read", "report only")
	// complexity=false asks for nothing.
	r.be.password = PasswordPolicy{MinLength: 12, MaxAgeDays: 60, Complexity: &off}
	expect(t, r.one(CheckPasswordPolicy, map[string]any{"minLength": 8.0, "complexity": false}, true), true, false)

	// Parameter validation.
	r = newRig(t)
	bad := []map[string]any{
		nil, {}, {"complexity": false}, {"minLength": 0.0}, {"minLength": 15.0}, {"minLength": "12"}, {"minLength": 8.5},
		{"maxAgeDays": 0.0}, {"maxAgeDays": 1000.0}, {"maxAgeDays": -1.0}, {"complexity": "yes"}, {"minLength": 8.0, "maxAgeDays": "/maxpwage:1 & calc"},
	}
	for _, params := range bad {
		got := r.one(CheckPasswordPolicy, params, true)
		if !strings.HasPrefix(got.Detail, DetailInvalidPrefix) || got.Compliant || got.Remediated {
			t.Errorf("%v: %+v", params, got)
		}
	}
	if len(r.be.calls) != 0 {
		t.Errorf("calls with invalid params: %v", r.be.calls)
	}
	// Not Windows.
	r.be.passErr = posture.Unsupportedf("password.policy is available on Windows only")
	if got := r.one(CheckPasswordPolicy, want, true); got.Detail != "not supported on this OS: password.policy is available on Windows only" {
		t.Errorf("%+v", got)
	}
}

func TestDiskEncryptionCheck(t *testing.T) {
	r := newRig(t)
	r.src.enc = []protocol.DiskEncryption{{Volume: "C:", Method: "bitlocker", Status: "encrypted"}, {Volume: "D:", Method: "bitlocker", Status: "encrypted"}}
	expect(t, r.one(CheckDiskEncryption, nil, false), true, false, "C: is encrypted (bitlocker); D: is encrypted (bitlocker)")

	// One volume not encrypted; remediate is ignored (report only).
	r.src.enc = []protocol.DiskEncryption{{Volume: "/", Method: "luks", Status: "encrypted"}, {Volume: "/srv/data", Method: "none", Status: "decrypted"}}
	expect(t, r.one(CheckDiskEncryption, nil, false), false, false, "/srv/data is decrypted")
	expect(t, r.one(CheckDiskEncryption, nil, true), false, false, "report only: disk encryption is never changed by the agent")
	// Suspended BitLocker and a conversion in progress are not compliant.
	r.src.enc = []protocol.DiskEncryption{{Volume: "C:", Method: "bitlocker", Status: "unknown"}}
	expect(t, r.one(CheckDiskEncryption, nil, true), false, false, "BitLocker protection is suspended")
	r.src.enc = []protocol.DiskEncryption{{Volume: "/", Method: "filevault", Status: "in_progress"}}
	expect(t, r.one(CheckDiskEncryption, nil, true), false, false, "/ is in_progress (filevault)")
	r.src.enc = []protocol.DiskEncryption{}
	expect(t, r.one(CheckDiskEncryption, nil, true), false, false, "no fixed volume was reported")
	if len(r.be.calls) != 0 || len(r.remediationLogs()) != 0 {
		t.Errorf("disk encryption was touched: %v", r.be.calls)
	}
	r.src.encErr = posture.Unsupportedf("the root file system is not on a block device listed by lsblk (container, ZFS or network root)")
	if got := r.one(CheckDiskEncryption, nil, true); !strings.HasPrefix(got.Detail, "not supported on this OS: the root file system") {
		t.Errorf("%+v", got)
	}
}

// ---- job level ----

func TestUnknownCheckAndJobValidation(t *testing.T) {
	r := newRig(t)
	results := r.run(
		protocol.PolicyCheck{PolicyID: "a", Check: "firewall.enabled"},
		protocol.PolicyCheck{PolicyID: "b", Check: "telemetry.disabled", Remediate: true},
		protocol.PolicyCheck{PolicyID: "c", Check: "Firewall.Enabled"},
		protocol.PolicyCheck{PolicyID: "", Check: "diskencryption.enabled"},
	)
	expect(t, results[0], true, false)
	for _, i := range []int{1, 2} {
		if results[i].Detail != "unknown check" || results[i].Compliant || results[i].Remediated {
			t.Errorf("result %d: %+v", i, results[i])
		}
	}
	if !strings.Contains(r.out.String(), "telemetry.disabled [b]: NOT COMPLIANT - unknown check") {
		t.Errorf("job output: %s", r.out.String())
	}
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}

	// An empty job is fine and yields an empty list (not null).
	res := r.h.Handle(r.jobContext(context.Background(), protocol.PolicyEvaluateSpec{}))
	raw, _ := json.Marshal(res.Result)
	if res.Status != protocol.StatusSucceeded || string(raw) != `{"results":[]}` {
		t.Errorf("empty job: %s %s", res.Status, raw)
	}

	// Malformed jobs are rejected as a whole; nothing runs.
	many := make([]protocol.PolicyCheck, MaxChecks+1)
	for i := range many {
		many[i] = protocol.PolicyCheck{PolicyID: "p", Check: CheckFirewall, Remediate: true}
	}
	rejected := []any{
		protocol.PolicyEvaluateSpec{Checks: many},
		protocol.PolicyEvaluateSpec{Checks: []protocol.PolicyCheck{{PolicyID: "p", Check: ""}}},
		protocol.PolicyEvaluateSpec{Checks: []protocol.PolicyCheck{{PolicyID: "p\nINFO forged log line", Check: CheckFirewall}}},
		protocol.PolicyEvaluateSpec{Checks: []protocol.PolicyCheck{{PolicyID: strings.Repeat("p", MaxPolicyIDBytes+1), Check: CheckFirewall}}},
		protocol.PolicyEvaluateSpec{Checks: []protocol.PolicyCheck{{PolicyID: "p", Check: strings.Repeat("c", MaxCheckNameBytes+1)}}},
		map[string]any{"checks": "all"},
		map[string]any{"checks": []any{map[string]any{"policyId": 7, "check": CheckFirewall}}},
	}
	r.src.fw = &protocol.FirewallState{Enabled: false, Detail: "off"}
	for i, spec := range rejected {
		if res := r.h.Handle(r.jobContext(context.Background(), spec)); res.Status != protocol.StatusRejected {
			t.Errorf("spec %d: status %s (%s)", i, res.Status, res.Message)
		}
	}
	if len(r.be.calls) != 0 {
		t.Errorf("a rejected job changed something: %v", r.be.calls)
	}

	// A cancelled job stops between checks and keeps what it has.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res = r.h.Handle(r.jobContext(ctx, protocol.PolicyEvaluateSpec{Checks: []protocol.PolicyCheck{{PolicyID: "p", Check: CheckFirewall, Remediate: true}}}))
	if res.Status == protocol.StatusSucceeded || len(r.be.calls) != 0 {
		t.Errorf("cancelled job: %s %v", res.Status, r.be.calls)
	}
}

func TestDetailIsBounded(t *testing.T) {
	r := newRig(t)
	r.src.fw = &protocol.FirewallState{Enabled: false, Detail: strings.Repeat("é", 5000) + "\xff"}
	got := r.one(CheckFirewall, nil, false)
	if len(got.Detail) > MaxDetailBytes || !strings.HasSuffix(got.Detail, "...") || strings.ContainsRune(got.Detail, '�') {
		t.Errorf("detail of %d bytes", len(got.Detail))
	}
	if _, err := json.Marshal(got); err != nil {
		t.Error(err)
	}
}

func TestErrOutcome(t *testing.T) {
	cases := map[error]string{
		posture.Unsupportedf("x"):                            "not supported on this OS: x",
		platform.ErrUnsupported:                              "not supported on this OS: this check is not available",
		fmt.Errorf("wrapped: %w", posture.Unsupportedf("y")): "not supported on this OS: y",
		platform.ErrNoConsoleUser:                            "not supported on this OS: no user is logged in",
		errors.New("boom\nsecond line"):                      "check failed: boom second line",
	}
	for err, want := range cases {
		if got := errOutcome(err); got.detail != want || got.compliant || got.remediated {
			t.Errorf("%v: %+v", err, got)
		}
	}
}
