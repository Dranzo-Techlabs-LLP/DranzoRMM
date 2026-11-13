package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/firewall"
)

type fakeFirewall struct {
	owned    []string
	enforced [][]firewall.Rule
	fail     error
	ownedErr error
}

func (f *fakeFirewall) Owned(context.Context) ([]string, error) { return f.owned, f.ownedErr }

func (f *fakeFirewall) Enforce(_ context.Context, rules []firewall.Rule) error {
	if f.fail != nil {
		return f.fail
	}
	f.enforced = append(f.enforced, rules)
	f.owned = nil
	for _, r := range rules {
		f.owned = append(f.owned, r.ID())
	}
	return nil
}

var smbRules = map[string]any{"rules": []any{
	map[string]any{"name": "Block SMB", "direction": "in", "action": "block", "protocol": "tcp", "ports": []any{"445"}},
	map[string]any{"name": "Block RDP", "direction": "in", "action": "block", "protocol": "tcp", "ports": []any{"3389"}},
}}

func TestFirewallRulesCheck(t *testing.T) {
	r := newRig(t)
	fw := &fakeFirewall{}
	r.h.WithFirewall(fw)

	// Report only: drift is reported, nothing is changed.
	expect(t, r.one(CheckFirewallRules, smbRules, false), false, false, "2 of 2 rules missing", "Block SMB")
	if len(fw.enforced) != 0 {
		t.Fatal("report-only check changed the firewall")
	}
	// Remediate: rules applied, then compliant without touching them again.
	expect(t, r.one(CheckFirewallRules, smbRules, true), true, true, "applied", "2 DranzoRMM firewall rules in place")
	expect(t, r.one(CheckFirewallRules, smbRules, true), true, false, "2 DranzoRMM firewall rules in place")
	if len(fw.enforced) != 1 {
		t.Errorf("enforced %d times", len(fw.enforced))
	}
	if logs := r.remediationLogs(); len(logs) != 1 || logs[0]["compliant_after"] != true {
		t.Errorf("remediation logs %v", logs)
	}
	// An outdated rule of ours (policy changed) counts as drift.
	fw.owned = append(fw.owned, "aaaaaaaaaaaaaaaa")
	expect(t, r.one(CheckFirewallRules, smbRules, false), false, false, "1 outdated DranzoRMM rules")
}

func TestFirewallRulesCheckFailuresAndInput(t *testing.T) {
	r := newRig(t)
	expect(t, r.one(CheckFirewallRules, smbRules, true), false, false, DetailUnsupportedPrefix)

	fw := &fakeFirewall{fail: errors.New("the server was unreachable after applying the rules, so the previous rules were restored")}
	r.h.WithFirewall(fw)
	expect(t, r.one(CheckFirewallRules, smbRules, true), false, false, "not applied", "previous rules were restored")
	expect(t, r.one(CheckFirewallRules, map[string]any{"rules": "nope"}, true), false, false, DetailInvalidPrefix)
	fw.ownedErr = firewall.ErrUnsupported
	expect(t, r.one(CheckFirewallRules, smbRules, true), false, false, "nftables")
}
