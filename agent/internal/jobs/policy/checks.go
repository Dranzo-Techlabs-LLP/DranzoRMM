package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/script"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ---- firewall.enabled ----

func (h *Handler) checkFirewall(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	fw, err := h.src.Firewall(jc.Ctx)
	if err != nil {
		return errOutcome(err)
	}
	if fw.Enabled {
		return outcome{compliant: true, detail: "firewall is on (" + fw.Detail + ")"}
	}
	before := "firewall is off (" + fw.Detail + ")"
	if !c.Remediate {
		return outcome{detail: before}
	}
	action, err := h.be.enableFirewall(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, "enable host firewall", before, before, false, err)
		return outcome{detail: notRemediated(before, err)}
	}
	after, err := h.src.Firewall(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, action, before, "unknown", false, err)
		return outcome{detail: before + "; " + action + "; the state could not be read afterwards: " + posture.OneLine(err.Error(), 300)}
	}
	state := "firewall is still off (" + after.Detail + ")"
	if after.Enabled {
		state = "firewall is on (" + after.Detail + ")"
	}
	logRemediation(jc, c, action, before, state, after.Enabled, nil)
	return outcome{compliant: after.Enabled, remediated: after.Enabled, detail: "was off; " + action + "; " + state}
}

// ---- antivirus.enabled ----

// isRealProduct excludes the informational Gatekeeper entry.
func isRealProduct(p protocol.AntivirusProduct) bool {
	return p.Source != posture.SourceXProtect || p.Name != posture.NameGatekeeper
}

func describeAntivirus(products []protocol.AntivirusProduct) string {
	if len(products) == 0 {
		return "no antivirus product found"
	}
	parts := make([]string, 0, len(products))
	for _, p := range products {
		s := posture.OneLine(p.Name, 80) + ": " + map[bool]string{true: "enabled", false: "disabled"}[p.Enabled]
		if isRealProduct(p) {
			if p.Source != posture.SourceKnownAV {
				s += map[bool]string{true: ", up to date", false: ", not up to date"}[p.UpToDate]
			}
			if p.SignatureVersion != "" {
				s += ", signatures " + posture.OneLine(p.SignatureVersion, 40)
			}
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// defenderRemediable decides whether the single permitted antivirus fix
// applies: Microsoft Defender, reported by Windows itself (Security Center
// or Defender status), is the only antivirus product and it is off. For
// anything else the reason names what has to be fixed where.
func defenderRemediable(products []protocol.AntivirusProduct) (ok bool, reason string) {
	var defender *protocol.AntivirusProduct
	var others []string
	for i, p := range products {
		if !isRealProduct(p) {
			continue
		}
		windowsSource := p.Source == posture.SourceWSC || p.Source == posture.SourceDefender
		if windowsSource && posture.IsDefenderName(p.Name) {
			defender = &products[i]
			continue
		}
		others = append(others, posture.OneLine(p.Name, 80))
	}
	switch {
	case len(others) > 0:
		return false, "the agent only re-enables Microsoft Defender on Windows; " + strings.Join(others, ", ") + " must be fixed in that product"
	case defender == nil:
		return false, "no antivirus product is installed and the agent never installs software"
	case defender.Enabled:
		return false, "Microsoft Defender is already enabled"
	}
	return true, ""
}

func (h *Handler) checkAntivirus(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	products, err := h.src.Antivirus(jc.Ctx)
	if err != nil {
		return errOutcome(err)
	}
	enabled := func(list []protocol.AntivirusProduct) bool {
		for _, p := range list {
			if isRealProduct(p) && p.Enabled {
				return true
			}
		}
		return false
	}
	before := describeAntivirus(products)
	if enabled(products) {
		return outcome{compliant: true, detail: before}
	}
	if !c.Remediate {
		return outcome{detail: "no enabled antivirus (" + before + ")"}
	}
	if ok, reason := defenderRemediable(products); !ok {
		return outcome{detail: "no enabled antivirus (" + before + "); not remediated: " + reason}
	}
	action, err := h.be.enableDefender(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, "enable Microsoft Defender real-time protection", before, before, false, err)
		return outcome{detail: notRemediated("no enabled antivirus ("+before+")", err)}
	}
	after, err := h.src.Antivirus(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, action, before, "unknown", false, err)
		return outcome{detail: before + "; " + action + "; the state could not be read afterwards: " + posture.OneLine(err.Error(), 300)}
	}
	ok := enabled(after)
	state := describeAntivirus(after)
	logRemediation(jc, c, action, before, state, ok, nil)
	detail := "was disabled; " + action + "; now: " + state
	if !ok {
		detail += " (still disabled: tamper protection or a policy may prevent the change)"
	}
	return outcome{compliant: ok, remediated: ok, detail: detail}
}

// ---- screenlock.timeout ----

func describeScreenLock(sl *protocol.ScreenLock) string {
	if sl == nil || !sl.Enabled {
		return "no automatic screen lock"
	}
	return fmt.Sprintf("screen locks after %d seconds", sl.TimeoutSeconds)
}

func (h *Handler) checkScreenLock(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	limit, present, err := intParam(c.Params, "maxSeconds", MinScreenLockSeconds, MaxScreenLockSeconds)
	if err != nil {
		return invalidOutcome(err)
	}
	if !present {
		return invalidOutcome(errors.New("maxSeconds is required"))
	}
	sl, err := h.src.ScreenLock(jc.Ctx)
	if err != nil {
		return errOutcome(err)
	}
	ok := func(s *protocol.ScreenLock) bool { return s != nil && s.Enabled && s.TimeoutSeconds <= limit }
	before := fmt.Sprintf("%s (required: at most %d)", describeScreenLock(sl), limit)
	if ok(sl) {
		return outcome{compliant: true, detail: before}
	}
	if !c.Remediate {
		return outcome{detail: before}
	}
	action, err := h.be.setScreenLockTimeout(jc.Ctx, limit)
	if err != nil {
		logRemediation(jc, c, fmt.Sprintf("set screen lock timeout to %d seconds", limit), before, before, false, err)
		return outcome{detail: notRemediated(before, err)}
	}
	after, err := h.src.ScreenLock(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, action, before, "unknown", false, err)
		return outcome{detail: before + "; " + action + "; the state could not be read afterwards: " + posture.OneLine(err.Error(), 300)}
	}
	good := ok(after)
	state := describeScreenLock(after)
	logRemediation(jc, c, action, before, state, good, nil)
	return outcome{compliant: good, remediated: good, detail: "was: " + describeScreenLock(sl) + "; " + action + "; now: " + state}
}

// ---- localadmins.allowed ----

func (h *Handler) checkLocalAdmins(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	allowed, err := accountListParam(c.Params, "allowed")
	if err != nil {
		return invalidOutcome(err)
	}
	current, err := h.src.LocalAdminAccounts(jc.Ctx)
	if err != nil {
		return errOutcome(err)
	}
	self := h.be.selfAccount()
	plan := planAdmins(current, allowed, self, h.be.accountKey)
	before := "administrators: " + strings.Join(posture.AdminNames(current), ", ")
	if len(plan.Extra) == 0 {
		return outcome{compliant: true, detail: before}
	}
	unexpected := "unexpected administrators: " + accountNames(plan.Extra)
	if !c.Remediate {
		return outcome{detail: unexpected}
	}

	var removed []posture.AdminAccount
	var failures []string
	for _, a := range plan.Remove {
		if jc.Ctx.Err() != nil {
			break
		}
		if err := h.be.removeAdmin(jc.Ctx, a); err != nil {
			failures = append(failures, displayName(a.Name)+" ("+posture.OneLine(err.Error(), 200)+")")
			continue
		}
		removed = append(removed, a)
	}

	after, err := h.src.LocalAdminAccounts(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, "remove from the administrators group: "+accountNames(removed), before, "unknown", false, err)
		return outcome{detail: unexpected + "; removed from the administrators group: " + accountNames(removed) +
			"; the state could not be read afterwards: " + posture.OneLine(err.Error(), 300)}
	}
	left := planAdmins(after, allowed, self, h.be.accountKey)
	good := len(left.Extra) == 0
	afterState := "administrators: " + strings.Join(posture.AdminNames(after), ", ")
	var logErr error
	if len(failures) > 0 {
		logErr = errors.New("could not remove: " + strings.Join(failures, ", "))
	}
	logRemediation(jc, c, "remove from the administrators group (accounts are not deleted): "+accountNames(removed), before, afterState, good, logErr)

	parts := []string{unexpected, "removed from the administrators group (accounts not deleted): " + accountNames(removed)}
	if len(plan.Kept) > 0 {
		parts = append(parts, "kept: "+keptList(plan.Kept))
	}
	if len(failures) > 0 {
		parts = append(parts, "could not remove: "+strings.Join(failures, ", "))
	}
	if !good {
		parts = append(parts, "still unexpected: "+accountNames(left.Extra))
	}
	return outcome{compliant: good, remediated: good && len(removed) > 0, detail: strings.Join(parts, "; ")}
}

// ---- usb.storage.blocked ----

func (h *Handler) checkUSBStorage(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	blocked, detail, err := h.be.usbStorage(jc.Ctx)
	if err != nil {
		return errOutcome(err)
	}
	if blocked {
		return outcome{compliant: true, detail: "USB mass storage is blocked (" + detail + ")"}
	}
	before := "USB mass storage is not blocked (" + detail + ")"
	if !c.Remediate {
		return outcome{detail: before}
	}
	action, err := h.be.blockUSBStorage(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, "disable the USB mass-storage driver", before, before, false, err)
		return outcome{detail: notRemediated(before, err)}
	}
	blocked, detail, err = h.be.usbStorage(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, action, before, "unknown", false, err)
		return outcome{detail: before + "; " + action + "; the state could not be read afterwards: " + posture.OneLine(err.Error(), 300)}
	}
	state := "USB mass storage is not blocked (" + detail + ")"
	if blocked {
		state = "USB mass storage is blocked (" + detail + "); a device that is already connected stays usable until it is unplugged"
	}
	logRemediation(jc, c, action, before, state, blocked, nil)
	return outcome{compliant: blocked, remediated: blocked, detail: "was not blocked; " + action + "; " + state}
}

// ---- password.policy ----

func passwordParams(params map[string]any) (passwordWant, error) {
	var w passwordWant
	if v, present, err := intParam(params, "minLength", MinPasswordLength, MaxPasswordLength); err != nil {
		return w, err
	} else if present {
		w.MinLength = &v
	}
	if v, present, err := intParam(params, "maxAgeDays", MinPasswordAge, MaxPasswordAge); err != nil {
		return w, err
	} else if present {
		w.MaxAgeDays = &v
	}
	if v, present, err := boolParam(params, "complexity"); err != nil {
		return w, err
	} else if present {
		w.Complexity = &v
	}
	if w.MinLength == nil && w.MaxAgeDays == nil && (w.Complexity == nil || !*w.Complexity) {
		return w, errors.New("at least one of minLength, maxAgeDays or complexity=true is required")
	}
	return w, nil
}

// complexityNote explains why the complexity requirement is report-only.
const complexityNote = "the complexity requirement is report only (set it by Group Policy or local security policy)"

func (h *Handler) checkPasswordPolicy(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	want, err := passwordParams(c.Params)
	if err != nil {
		return invalidOutcome(err)
	}
	cur, err := h.be.passwordPolicy(jc.Ctx)
	if err != nil {
		return errOutcome(err)
	}
	gaps, setMin, setMax, complexityGap := passwordGaps(cur, want)
	before := describePassword(cur)
	if len(gaps) == 0 {
		return outcome{compliant: true, detail: before}
	}
	problem := strings.Join(gaps, "; ") + " (current: " + before + ")"
	if !c.Remediate {
		return outcome{detail: problem}
	}
	if setMin == nil && setMax == nil {
		return outcome{detail: problem + "; not remediated: " + complexityNote}
	}
	action, err := h.be.setPasswordPolicy(jc.Ctx, setMin, setMax)
	if err != nil {
		logRemediation(jc, c, "tighten the local password policy", before, before, false, err)
		return outcome{detail: notRemediated(problem, err)}
	}
	after, err := h.be.passwordPolicy(jc.Ctx)
	if err != nil {
		logRemediation(jc, c, action, before, "unknown", false, err)
		return outcome{detail: problem + "; " + action + "; the state could not be read afterwards: " + posture.OneLine(err.Error(), 300)}
	}
	left, _, _, _ := passwordGaps(after, want)
	good := len(left) == 0
	state := describePassword(after)
	logRemediation(jc, c, action, before, state, good, nil)
	detail := "was: " + before + "; " + action + "; now: " + state
	if !good {
		detail += "; still not compliant: " + strings.Join(left, "; ")
		if complexityGap {
			detail += "; " + complexityNote
		}
	}
	return outcome{compliant: good, remediated: good, detail: detail}
}

// ---- diskencryption.enabled ----

func (h *Handler) checkDiskEncryption(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	vols, err := h.src.DiskEncryption(jc.Ctx)
	if err != nil {
		return errOutcome(err)
	}
	if len(vols) == 0 {
		return outcome{detail: "no fixed volume was reported"}
	}
	good := true
	parts := make([]string, 0, len(vols))
	for _, v := range vols {
		s := posture.OneLine(v.Volume, 80) + " is " + v.Status
		if v.Method != posture.MethodNone && v.Method != "" {
			s += " (" + v.Method + ")"
		}
		if v.Status == posture.StatusUnknown && v.Method == posture.MethodBitLocker {
			s += " - BitLocker protection is suspended or its state could not be determined"
		}
		if v.Status != posture.StatusEncrypted {
			good = false
		}
		parts = append(parts, s)
	}
	detail := strings.Join(parts, "; ")
	if !good && c.Remediate {
		// Report only: the protocol says remediate is ignored for this check.
		detail += "; report only: disk encryption is never changed by the agent"
	}
	return outcome{compliant: good, detail: detail}
}

// ---- script ----

// Bounds of the output captured from a check / remediation script.
const (
	scriptCaptureBytes = 8 << 10
	scriptDetailBytes  = 1500
)

// tailBuffer keeps the last limit bytes written to it.
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if extra := len(b.buf) - b.limit; extra > 0 {
		b.buf = append(b.buf[:0], b.buf[extra:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := strings.ToValidUTF8(string(bytes.TrimSpace(b.buf)), "?")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > scriptDetailBytes {
		cut := len(s) - scriptDetailBytes
		for cut < len(s) && s[cut]&0xC0 == 0x80 {
			cut++
		}
		s = "..." + s[cut:]
	}
	return s
}

// runScript runs body through the script job handler (same validation,
// protected temporary file, argv execution and process-tree kill as the
// "script" kind), as the system, capturing a bounded tail of its output.
func (h *Handler) runScript(jc *jobs.JobContext, language, body string) (jobs.Result, string) {
	raw, err := json.Marshal(protocol.ScriptSpec{Language: language, Body: body, RunAs: protocol.RunAsSystem})
	if err != nil {
		return jobs.Failed("%v", err), ""
	}
	out := &tailBuffer{limit: scriptCaptureBytes}
	sub := *jc
	sub.Spec = raw
	sub.Stdout = out
	sub.Stderr = out
	res := h.script.Handle(&sub)
	return res, out.text()
}

func scriptState(what string, res jobs.Result) string {
	if res.ExitCode != nil {
		return fmt.Sprintf("%s exit code %d", what, *res.ExitCode)
	}
	return what + " did not run to completion: " + posture.OneLine(res.Message, 200)
}

func (h *Handler) checkScript(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	language, _, err := stringParam(c.Params, "language", 32)
	if err != nil {
		return invalidOutcome(err)
	}
	check, _, err := stringParam(c.Params, "checkScript", script.MaxBodyBytes)
	if err != nil {
		return invalidOutcome(err)
	}
	fix, haveFix, err := stringParam(c.Params, "remediationScript", script.MaxBodyBytes)
	if err != nil {
		return invalidOutcome(err)
	}
	// Validate both scripts before running anything.
	spec := protocol.ScriptSpec{Language: language, Body: check}
	if err := script.Validate(&spec); err != nil {
		return invalidOutcome(fmt.Errorf("checkScript: %w", err))
	}
	haveFix = haveFix && strings.TrimSpace(fix) != ""
	if haveFix {
		fixSpec := protocol.ScriptSpec{Language: language, Body: fix}
		if err := script.Validate(&fixSpec); err != nil {
			return invalidOutcome(fmt.Errorf("remediationScript: %w", err))
		}
	}

	withOutput := func(detail, output string) string {
		if output == "" {
			return detail
		}
		return detail + "; output: " + output
	}
	// special maps the results that are not a plain exit code.
	special := func(res jobs.Result) (outcome, bool) {
		switch res.Status {
		case protocol.StatusUnsupported:
			msg := res.Message
			if !strings.HasPrefix(msg, DetailUnsupportedPrefix) {
				msg = DetailUnsupportedPrefix + msg
			}
			return outcome{detail: msg}, true
		case protocol.StatusRejected:
			return outcome{detail: DetailInvalidPrefix + res.Message}, true
		}
		if res.ExitCode == nil && res.Status != protocol.StatusSucceeded {
			return outcome{detail: DetailFailedPrefix + posture.OneLine(res.Message, 300)}, true
		}
		return outcome{}, false
	}

	res, output := h.runScript(jc, language, check)
	if o, ok := special(res); ok {
		return o
	}
	if res.Status == protocol.StatusSucceeded {
		return outcome{compliant: true, detail: withOutput(scriptState("check", res), output)}
	}
	before := scriptState("check", res)
	if !c.Remediate {
		return outcome{detail: withOutput(before, output)}
	}
	if !haveFix {
		return outcome{detail: withOutput(before+"; not remediated: no remediationScript was given", output)}
	}
	if jc.Ctx.Err() != nil {
		return outcome{detail: withOutput(before+"; interrupted before remediation", output)}
	}
	fixRes, fixOutput := h.runScript(jc, language, fix)
	fixState := scriptState("remediation", fixRes)
	if jc.Ctx.Err() != nil {
		logRemediation(jc, c, "run remediation script", before, "unknown", false, jc.Ctx.Err())
		return outcome{detail: withOutput(before+"; "+fixState+"; interrupted before the re-check", fixOutput)}
	}
	again, againOutput := h.runScript(jc, language, check)
	good := again.Status == protocol.StatusSucceeded
	after := scriptState("re-check", again)
	logRemediation(jc, c, "run remediation script ("+fixState+")", before, after, good, nil)
	detail := before + "; " + fixState + "; " + after
	if good {
		return outcome{compliant: true, remediated: true, detail: withOutput(detail, againOutput)}
	}
	return outcome{detail: withOutput(detail, strings.TrimSpace(fixOutput+" "+againOutput))}
}
