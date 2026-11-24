package firewall

import (
	"strings"
	"testing"
)

// "powershell -Command -" exits with 1 when its last statement failed, even
// when that statement's error was silenced with -ErrorAction
// SilentlyContinue. A Get-NetFirewallRule that finds nothing (no DranzoRMM
// rules yet) is such a failure, so it must never be the last statement of a
// script whose exit code is checked.
func TestWindowsScriptsDoNotEndWithAFailableLookup(t *testing.T) {
	for name, script := range map[string]string{
		"PSListRules":        PSListRules,
		"PSApplyRules":       PSApplyRules,
		"PSIsolate":          PSIsolate,
		"PSReleaseIsolation": PSReleaseIsolation,
		"PSIsolationKeep":    PSIsolationKeep,
	} {
		lines := strings.Split(strings.TrimSpace(script), "\n")
		last := strings.TrimSpace(lines[len(lines)-1])
		if strings.Contains(last, "-ErrorAction SilentlyContinue") || strings.HasPrefix(last, "Get-NetFirewallRule") {
			t.Errorf("%s ends with a lookup that may find nothing: %q", name, last)
		}
	}
	if !strings.Contains(PSListRules, "$rules = @(Get-NetFirewallRule -Group 'DranzoRMM'") {
		t.Error("PSListRules must collect the rules before printing them")
	}
}
