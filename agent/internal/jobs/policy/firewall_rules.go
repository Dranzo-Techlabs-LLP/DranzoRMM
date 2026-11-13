package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/firewall"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ---- firewall.rules ----

// checkFirewallRules compares the rules DranzoRMM owns in the host firewall
// with the policy's rules and, with remediate, replaces them. Rules of other
// software and of the user are never touched.
func (h *Handler) checkFirewallRules(jc *jobs.JobContext, c protocol.PolicyCheck) outcome {
	if h.fw == nil {
		return unsupportedOutcome("firewall rules are not available in this agent")
	}
	rules, err := firewall.ParseRules(c.Params["rules"])
	if err != nil {
		return invalidOutcome(err)
	}
	want, skipped := firewall.Applicable(rules, firewall.SupportsPrograms)
	note := ""
	if len(skipped) > 0 {
		note = fmt.Sprintf("; skipped (program rules are Windows only): %s", strings.Join(skipped, ", "))
	}
	owned, err := h.fw.Owned(jc.Ctx)
	if errors.Is(err, firewall.ErrUnsupported) {
		return unsupportedOutcome("no supported firewall tool on this computer (nftables on Linux)")
	}
	if err != nil {
		return errOutcome(err)
	}
	missing, unexpected := firewall.Diff(owned, want)
	if len(missing) == 0 && len(unexpected) == 0 {
		return outcome{compliant: true, detail: fmt.Sprintf("%d DranzoRMM firewall rules in place%s", len(want), note)}
	}
	names := make([]string, 0, len(missing))
	for _, r := range missing {
		names = append(names, r.Name)
	}
	before := fmt.Sprintf("%d of %d rules missing", len(missing), len(want))
	if len(names) > 0 {
		before += " (" + strings.Join(names, ", ") + ")"
	}
	if len(unexpected) > 0 {
		before += fmt.Sprintf("; %d outdated DranzoRMM rules", len(unexpected))
	}
	if !c.Remediate {
		return outcome{detail: before + note}
	}
	if err := h.fw.Enforce(jc.Ctx, want); err != nil {
		logRemediation(jc, c, "replace DranzoRMM firewall rules", before, before, false, err)
		return outcome{detail: before + "; not applied: " + posture.OneLine(err.Error(), 500) + note}
	}
	after := fmt.Sprintf("%d DranzoRMM firewall rules in place", len(want))
	logRemediation(jc, c, "replace DranzoRMM firewall rules", before, after, true, nil)
	return outcome{compliant: true, remediated: true, detail: before + "; applied; " + after + note}
}
