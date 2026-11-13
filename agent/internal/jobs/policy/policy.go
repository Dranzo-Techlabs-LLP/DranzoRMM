// Package policy implements the "policy.evaluate" job kind (PROTOCOL.md
// section 6.2): desired-state checks with optional remediation.
//
// Every check reads the current state (mostly through the posture
// collector), decides compliance and, when the server asked for remediation
// and the device is not compliant, applies one narrowly defined fix and reads
// the state again. The result of a check is {policyId, check, compliant,
// remediated, detail}:
//
//   - compliant is the state at the end (after any remediation);
//   - remediated is true only when a fix was applied and the re-check passed;
//   - detail explains the state, and lists exactly what was changed.
//
// Detail conventions the server relies on:
//
//	"not supported on this OS: ..."  the check cannot be evaluated on this
//	                                 OS / edition / in the current state
//	"unknown check"                  the check name is not known to this agent
//	"invalid parameters: ..."        params failed validation; nothing was done
//	"check failed: ..."              the state could not be read (an error)
//
// In all four cases compliant and remediated are false.
//
// Safety rules of the remediations (see also SPEC.md section 1):
//
//   - Security products are only ever switched ON. The one antivirus fix is
//     re-enabling Microsoft Defender real-time protection through its
//     supported cmdlet. Nothing here disables, uninstalls or reconfigures a
//     security product, and nothing installs software.
//   - localadmins.allowed removes accounts from the administrators group
//     only. It never deletes an account, and never removes the built-in
//     Administrator / root, the last remaining administrator or the account
//     the agent runs as.
//   - Values from the server are validated first and reach the operating
//     system only as argv elements or environment variables, never as part of
//     a command line or script text.
//   - Every remediation writes one structured log line (what, before, after).
package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/dranzo/dranzormm/agent/internal/firewall"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/script"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Built-in check names (PROTOCOL.md section 6.2).
const (
	CheckFirewall       = "firewall.enabled"
	CheckAntivirus      = "antivirus.enabled"
	CheckScreenLock     = "screenlock.timeout"
	CheckLocalAdmins    = "localadmins.allowed"
	CheckUSBStorage     = "usb.storage.blocked"
	CheckPasswordPolicy = "password.policy"
	CheckDiskEncryption = "diskencryption.enabled"
	CheckScript         = "script"
	CheckFirewallRules  = "firewall.rules"
)

// Detail prefixes (see the package comment).
const (
	DetailUnsupportedPrefix = posture.UnsupportedPrefix
	DetailUnknownCheck      = "unknown check"
	DetailInvalidPrefix     = "invalid parameters: "
	DetailFailedPrefix      = "check failed: "
)

// Limits.
const (
	// MaxChecks is the number of checks one job may carry.
	MaxChecks = 64
	// MaxDetailBytes bounds PolicyCheckResult.Detail.
	MaxDetailBytes = 4096
	// MaxPolicyIDBytes and MaxCheckNameBytes bound the identifiers.
	MaxPolicyIDBytes  = 128
	MaxCheckNameBytes = 64
)

// Source is the read side of the checks; *posture.Collector implements it.
type Source interface {
	Antivirus(ctx context.Context) ([]protocol.AntivirusProduct, error)
	Firewall(ctx context.Context) (*protocol.FirewallState, error)
	DiskEncryption(ctx context.Context) ([]protocol.DiskEncryption, error)
	LocalAdminAccounts(ctx context.Context) ([]posture.AdminAccount, error)
	ScreenLock(ctx context.Context) (*protocol.ScreenLock, error)
}

// backend is the per-OS write side (and the Windows-only readers). The
// implementations live in backend_windows.go, backend_darwin.go and
// backend_linux.go. A method that the OS cannot provide returns a
// *posture.UnsupportedError (the check is not available) or a
// *reportOnlyError (the check works, the fix does not exist here).
type backend interface {
	// enableFirewall turns the host firewall on and says what it did.
	enableFirewall(ctx context.Context) (action string, err error)
	// enableDefender re-enables Microsoft Defender real-time protection. It
	// is the only antivirus remediation, and it only switches protection on.
	enableDefender(ctx context.Context) (action string, err error)
	// setScreenLockTimeout sets the machine-wide inactivity lock.
	setScreenLockTimeout(ctx context.Context, seconds int) (action string, err error)
	// removeAdmin removes one account from the administrators group. The
	// account itself is never deleted or disabled.
	removeAdmin(ctx context.Context, account posture.AdminAccount) error
	// selfAccount is the account the agent runs as.
	selfAccount() string
	// accountKey normalises an account name for comparison.
	accountKey(name string) string
	// usbStorage reads whether USB mass storage is blocked.
	usbStorage(ctx context.Context) (blocked bool, detail string, err error)
	// blockUSBStorage disables the USB mass-storage driver.
	blockUSBStorage(ctx context.Context) (action string, err error)
	// passwordPolicy reads the local password policy.
	passwordPolicy(ctx context.Context) (PasswordPolicy, error)
	// setPasswordPolicy tightens the minimum length and / or maximum age
	// (nil leaves a value unchanged).
	setPasswordPolicy(ctx context.Context, minLength, maxAgeDays *int) (action string, err error)
}

// reportOnlyError says that a check has no remediation on this OS (or for
// this product). The check result stands; the reason goes into the detail.
type reportOnlyError struct{ reason string }

func (e *reportOnlyError) Error() string { return e.reason }

func reportOnlyf(format string, args ...any) error {
	return &reportOnlyError{reason: fmt.Sprintf(format, args...)}
}

// Firewall applies the rules DranzoRMM owns; *firewall.Manager implements it.
type Firewall interface {
	Owned(ctx context.Context) ([]string, error)
	Enforce(ctx context.Context, rules []firewall.Rule) error
}

// Handler is the jobs.Handler for the "policy.evaluate" kind.
type Handler struct {
	src    Source
	be     backend
	script jobs.Handler
	fw     Firewall
}

// WithFirewall enables the firewall.rules check.
func (h *Handler) WithFirewall(fw Firewall) *Handler {
	h.fw = fw
	return h
}

// New returns the handler. src is the posture collector; p runs the
// remediation commands.
func New(src Source, p platform.Platform) *Handler {
	return &Handler{src: src, be: newBackend(p), script: script.New()}
}

// outcome is the result of one check before it is put on the wire.
type outcome struct {
	compliant  bool
	remediated bool
	detail     string
}

func unsupportedOutcome(reason string) outcome {
	return outcome{detail: DetailUnsupportedPrefix + reason}
}

func invalidOutcome(err error) outcome {
	return outcome{detail: DetailInvalidPrefix + err.Error()}
}

// errOutcome maps a state-reading error to an outcome.
func errOutcome(err error) outcome {
	var ue *posture.UnsupportedError
	switch {
	case errors.As(err, &ue):
		return unsupportedOutcome(ue.Reason)
	case errors.Is(err, platform.ErrUnsupported):
		reason := strings.TrimPrefix(err.Error(), DetailUnsupportedPrefix)
		if reason == platform.ErrUnsupported.Error() {
			reason = "this check is not available"
		}
		return unsupportedOutcome(posture.OneLine(reason, 500))
	case errors.Is(err, platform.ErrNoConsoleUser):
		return unsupportedOutcome("no user is logged in")
	}
	return outcome{detail: DetailFailedPrefix + posture.OneLine(err.Error(), 500)}
}

// boundDetail makes a detail safe to send: valid UTF-8, bounded.
func boundDetail(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= MaxDetailBytes {
		return s
	}
	cut := MaxDetailBytes - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func validIdentifier(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Handle implements jobs.Handler.
func (h *Handler) Handle(jc *jobs.JobContext) jobs.Result {
	var spec protocol.PolicyEvaluateSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if len(spec.Checks) > MaxChecks {
		return jobs.Rejected("more than %d checks", MaxChecks)
	}
	for i, c := range spec.Checks {
		if !validIdentifier(c.PolicyID, MaxPolicyIDBytes) {
			return jobs.Rejected("checks[%d].policyId is invalid", i)
		}
		if c.Check == "" || !validIdentifier(c.Check, MaxCheckNameBytes) {
			return jobs.Rejected("checks[%d].check is invalid", i)
		}
	}

	results := make([]protocol.PolicyCheckResult, 0, len(spec.Checks))
	for _, c := range spec.Checks {
		if jc.Ctx.Err() != nil {
			// Cancelled or timed out: report what was evaluated so far (the
			// manager turns the status into cancelled / timeout).
			return jobs.Result{Status: protocol.StatusFailed, Message: "interrupted", Result: protocol.PolicyEvaluateResult{Results: results}}
		}
		o := h.evaluate(jc, c)
		o.detail = boundDetail(o.detail)
		results = append(results, protocol.PolicyCheckResult{
			PolicyID:   c.PolicyID,
			Check:      c.Check,
			Compliant:  o.compliant,
			Remediated: o.remediated,
			Detail:     o.detail,
		})
		state := "NOT COMPLIANT"
		switch {
		case o.remediated:
			state = "REMEDIATED"
		case o.compliant:
			state = "compliant"
		}
		_, _ = fmt.Fprintf(jc.Stdout, "%s [%s]: %s - %s\n", c.Check, c.PolicyID, state, o.detail)
		jc.Log.Info("policy check",
			slog.String("policy_id", c.PolicyID), slog.String("check", c.Check),
			slog.Bool("compliant", o.compliant), slog.Bool("remediated", o.remediated),
			slog.Bool("remediate_requested", c.Remediate))
	}
	return jobs.SucceededWith(protocol.PolicyEvaluateResult{Results: results})
}

func (h *Handler) evaluate(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	switch c.Check {
	case CheckFirewall:
		return h.checkFirewall(jc, c)
	case CheckAntivirus:
		return h.checkAntivirus(jc, c)
	case CheckScreenLock:
		return h.checkScreenLock(jc, c)
	case CheckLocalAdmins:
		return h.checkLocalAdmins(jc, c)
	case CheckUSBStorage:
		return h.checkUSBStorage(jc, c)
	case CheckPasswordPolicy:
		return h.checkPasswordPolicy(jc, c)
	case CheckDiskEncryption:
		return h.checkDiskEncryption(jc, c)
	case CheckScript:
		return h.checkScript(jc, c)
	case CheckFirewallRules:
		return h.checkFirewallRules(jc, c)
	}
	return outcome{detail: DetailUnknownCheck}
}

// logRemediation writes the one structured log line of a remediation: what
// was done, the state before and the state after.
func logRemediation(jc *jobs.JobContext, c protocol.PolicyCheck, action, before, after string, compliant bool, err error) {
	attrs := []any{
		slog.String("policy_id", c.PolicyID),
		slog.String("check", c.Check),
		slog.String("action", posture.OneLine(action, 500)),
		slog.String("before", posture.OneLine(before, 500)),
		slog.String("after", posture.OneLine(after, 500)),
		slog.Bool("compliant_after", compliant),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", posture.OneLine(err.Error(), 500)))
		jc.Log.Warn("policy remediation", attrs...)
		return
	}
	jc.Log.Info("policy remediation", attrs...)
}

// notRemediated formats the detail of a fix that could not be applied.
func notRemediated(state string, err error) string {
	var ro *reportOnlyError
	var ue *posture.UnsupportedError
	switch {
	case errors.As(err, &ro):
		return state + "; not remediated: " + ro.reason
	case errors.As(err, &ue):
		return state + "; not remediated: remediation is not available on this OS (" + ue.Reason + ")"
	}
	return state + "; remediation failed: " + posture.OneLine(err.Error(), 500)
}
