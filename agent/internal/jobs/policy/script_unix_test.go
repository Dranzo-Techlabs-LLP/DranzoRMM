//go:build !windows

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs/script"
)

func TestScriptCheck(t *testing.T) {
	r := newRig(t)
	expect(t, r.one(CheckScript, map[string]any{"language": "sh", "checkScript": "exit 0"}, true), true, false, "check exit code 0")

	// Not compliant: the exit code and a bounded tail of the output.
	got := r.one(CheckScript, map[string]any{"language": "sh", "checkScript": "echo 'setting is wrong'; echo detail >&2; exit 3"}, false)
	expect(t, got, false, false, "check exit code 3", "output: setting is wrong detail")

	// Remediation requested without a remediation script.
	got = r.one(CheckScript, map[string]any{"language": "sh", "checkScript": "exit 1"}, true)
	expect(t, got, false, false, "check exit code 1; not remediated: no remediationScript was given")

	// Check fails, remediation fixes it, re-check passes.
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	ran := filepath.Join(dir, "remediation-ran")
	params := map[string]any{
		"language":          "sh",
		"checkScript":       "test -f '" + marker + "'",
		"remediationScript": "touch '" + marker + "' '" + ran + "'; echo fixed",
	}
	// remediate=false never runs the remediation script.
	expect(t, r.one(CheckScript, params, false), false, false, "check exit code 1")
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the remediation script ran without remediate")
	}
	got = r.one(CheckScript, params, true)
	expect(t, got, true, true, "check exit code 1; remediation exit code 0; re-check exit code 0")
	logs := r.remediationLogs()
	if len(logs) != 1 || logs[0]["before"] != "check exit code 1" || logs[0]["after"] != "re-check exit code 0" ||
		logs[0]["action"] != "run remediation script (remediation exit code 0)" || logs[0]["compliant_after"] != true {
		t.Errorf("log: %v", logs)
	}
	// Already compliant now: the remediation script is not run again.
	_ = os.Remove(ran)
	expect(t, r.one(CheckScript, params, true), true, false, "check exit code 0")
	if _, err := os.Stat(ran); err == nil {
		t.Error("the remediation script ran on a compliant device")
	}

	// The remediation runs but does not fix it.
	got = r.one(CheckScript, map[string]any{"language": "sh", "checkScript": "echo still broken; exit 2", "remediationScript": "echo tried; exit 5"}, true)
	expect(t, got, false, false, "check exit code 2; remediation exit code 5; re-check exit code 2", "tried", "still broken")

	// Script bodies never reach the log.
	if log := r.log.String(); strings.Contains(log, "still broken") || strings.Contains(log, "touch") {
		t.Errorf("a script body was logged: %s", log)
	}
}

func TestScriptCheckValidation(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "check-ran")
	touch := "touch '" + marker + "'; exit 1"
	bad := []map[string]any{
		nil,
		{},
		{"language": "sh"},
		{"language": "sh", "checkScript": ""},
		{"language": "perl", "checkScript": touch},
		{"language": "", "checkScript": touch},
		{"language": 7.0, "checkScript": touch},
		{"language": "sh", "checkScript": []any{touch}},
		{"language": "sh", "checkScript": touch + "\x00"},
		{"language": "sh", "checkScript": strings.Repeat("#", script.MaxBodyBytes+1)},
		// A bad remediation script is refused before the check runs.
		{"language": "sh", "checkScript": touch, "remediationScript": "echo \x00"},
		{"language": "sh", "checkScript": touch, "remediationScript": 5.0},
		{"language": "sh", "checkScript": touch, "remediationScript": strings.Repeat("#", script.MaxBodyBytes+1)},
	}
	r := newRig(t)
	for _, params := range bad {
		got := r.one(CheckScript, params, true)
		if !strings.HasPrefix(got.Detail, DetailInvalidPrefix) || got.Compliant || got.Remediated {
			t.Errorf("%.60v: %+v", params, got)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a script ran although the parameters were invalid")
	}

	// A language this OS cannot run is "not supported on this OS".
	got := r.one(CheckScript, map[string]any{"language": "cmd", "checkScript": "exit /b 0"}, true)
	if !strings.HasPrefix(got.Detail, "not supported on this OS: cmd scripts run only on Windows") || got.Compliant {
		t.Errorf("%+v", got)
	}
}

func TestScriptCheckOutputIsBounded(t *testing.T) {
	r := newRig(t)
	// 200 kB of output with control characters: the detail keeps a clean tail.
	body := "i=0; while [ $i -lt 2000 ]; do printf '%0100d\\033[31m\\n' $i; i=$((i+1)); done; echo THE-END; exit 1"
	got := r.one(CheckScript, map[string]any{"language": "sh", "checkScript": body}, false)
	expect(t, got, false, false, "check exit code 1; output: ...", "THE-END")
	if len(got.Detail) > MaxDetailBytes || strings.ContainsAny(got.Detail, "\x1b\n\r") {
		t.Errorf("detail of %d bytes: %.80q", len(got.Detail), got.Detail)
	}
	// The job output carries the summary line, not the script's raw output.
	if strings.Count(r.out.String(), "\n") != 1 {
		t.Errorf("job output has %d lines", strings.Count(r.out.String(), "\n"))
	}
}
