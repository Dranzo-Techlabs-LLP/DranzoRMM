package policy

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/posture"
)

func names(accounts []posture.AdminAccount) []string {
	out := []string{}
	for _, a := range accounts {
		out = append(out, a.Name)
	}
	return out
}

func kept(plan adminPlan) map[string]string {
	out := map[string]string{}
	for _, k := range plan.Kept {
		out[k.Name] = k.Reason
	}
	return out
}

func TestValidAccountName(t *testing.T) {
	good := []string{
		"alice", "bob.smith", "svc_backup", "j-doe", "user1", "_mbsetupuser", "Domain Admins", `CONTOSO\Domain Admins`,
		`AzureAD\JaneDoe`, "jane@contoso.com", "WORKSTATION$", `CORP\gmsa-web$`, "Müller", "Администратор", "a",
	}
	for _, n := range good {
		if !ValidAccountName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	bad := []string{
		"", " ", "bob; rm -rf /", "$(id)", "`id`", "bob`id`", "bob|cat", "bob&calc", "bob>out", "bob<in", "bob'", `bob"`,
		"-rf", "--help", "/etc/passwd", "../admin", "a/b", `a\b\c`, `\bob`, `bob\`, "bob\n", "bob\nroot", "bob\x00", "bob\t",
		" bob", "bob ", "bob  smith", `CORP \bob`, `CORP\ bob`, "$bob", "bo$b", "bob*", "bob?", "b{o}b", "bob=1", "bob,carol",
		"bob:x:0:0", "%USERNAME%", "bob!", "bob#", "bob(1)", "bob\xff", strings.Repeat("a", 129), `S-1-5-21-1-2-3-1001; whoami`,
	}
	for _, n := range bad {
		if ValidAccountName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestPlanAdmins(t *testing.T) {
	root := posture.AdminAccount{Name: "root", Builtin: true, Primary: true}
	acct := func(name string) posture.AdminAccount {
		return posture.AdminAccount{Name: name, Groups: []string{"sudo"}}
	}
	fold := strings.ToLower

	// Everyone allowed.
	plan := planAdmins([]posture.AdminAccount{root, acct("alice")}, []string{"alice"}, "root", nil)
	if len(plan.Extra)+len(plan.Remove)+len(plan.Kept) != 0 {
		t.Errorf("compliant: %+v", plan)
	}
	// The built-in administrator never needs to be listed.
	plan = planAdmins([]posture.AdminAccount{root}, nil, "root", nil)
	if len(plan.Extra) != 0 {
		t.Errorf("builtin only: %+v", plan)
	}
	// Two extras next to an allowed admin: both removed, in name order.
	plan = planAdmins([]posture.AdminAccount{acct("zed"), root, acct("alice"), acct("bob")}, []string{"alice"}, "root", nil)
	if !reflect.DeepEqual(names(plan.Extra), []string{"bob", "zed"}) || !reflect.DeepEqual(names(plan.Remove), []string{"bob", "zed"}) || len(plan.Kept) != 0 {
		t.Errorf("two extras: %+v", plan)
	}

	// Guard rail: the built-in administrator is never removed, even when
	// the allowed list is empty and names nobody.
	plan = planAdmins([]posture.AdminAccount{root, {Name: "Administrator", Builtin: true}}, []string{}, "", nil)
	if len(plan.Remove) != 0 || len(plan.Extra) != 0 {
		t.Errorf("builtin: %+v", plan)
	}

	// Guard rail: the last remaining administrator stays. Built-in accounts
	// do not count as "remaining".
	plan = planAdmins([]posture.AdminAccount{root, acct("bob"), acct("carol")}, []string{"itadmin"}, "root", nil)
	if !reflect.DeepEqual(names(plan.Remove), []string{"bob"}) || kept(plan)["carol"] != keepLastAdmin {
		t.Errorf("last admin: remove %v kept %v", names(plan.Remove), kept(plan))
	}
	plan = planAdmins([]posture.AdminAccount{root, acct("bob")}, nil, "root", nil)
	if len(plan.Remove) != 0 || kept(plan)["bob"] != keepLastAdmin || len(plan.Extra) != 1 {
		t.Errorf("single extra: %+v", plan)
	}
	// With an allowed administrator present, every extra can go.
	plan = planAdmins([]posture.AdminAccount{root, acct("bob"), acct("itadmin")}, []string{"itadmin"}, "root", nil)
	if !reflect.DeepEqual(names(plan.Remove), []string{"bob"}) || len(plan.Kept) != 0 {
		t.Errorf("allowed present: %+v", plan)
	}

	// Guard rail: the account the agent runs as is never removed (it still
	// counts as unexpected, and as a remaining administrator).
	plan = planAdmins([]posture.AdminAccount{root, acct("agentsvc"), acct("bob")}, nil, "agentsvc", nil)
	if !reflect.DeepEqual(names(plan.Remove), []string{"bob"}) || kept(plan)["agentsvc"] != keepSelf || len(plan.Extra) != 2 {
		t.Errorf("self: remove %v kept %v", names(plan.Remove), kept(plan))
	}
	// Case-insensitive systems: "AgentSvc" is the same account.
	plan = planAdmins([]posture.AdminAccount{acct("AgentSvc"), acct("Bob"), acct("carol")}, []string{"CAROL"}, "agentsvc", fold)
	if !reflect.DeepEqual(names(plan.Remove), []string{"Bob"}) || kept(plan)["AgentSvc"] != keepSelf {
		t.Errorf("self, case-insensitive: remove %v kept %v", names(plan.Remove), kept(plan))
	}
	// Case-sensitive systems (Linux): "Alice" is not "alice".
	plan = planAdmins([]posture.AdminAccount{acct("Alice"), acct("alice")}, []string{"alice"}, "root", nil)
	if !reflect.DeepEqual(names(plan.Remove), []string{"Alice"}) {
		t.Errorf("case-sensitive: %+v", plan)
	}

	// Accounts a group edit cannot fix, and names that are not plain
	// account names, are reported but never passed to a tool.
	current := []posture.AdminAccount{
		root, acct("alice"),
		{Name: "toor", Primary: true},
		{Name: "carol", Primary: true, Groups: []string{"sudo"}},
		acct("bob; rm -rf /"), acct("$(id)"), acct("-rf"),
	}
	plan = planAdmins(current, []string{"alice"}, "root", nil)
	if len(plan.Remove) != 0 || len(plan.Extra) != 5 {
		t.Errorf("unremovable: remove %v extra %v", names(plan.Remove), names(plan.Extra))
	}
	k := kept(plan)
	if k["toor"] != keepPrimary || k["carol"] != keepPrimary || k["bob; rm -rf /"] != keepBadName || k["$(id)"] != keepBadName || k["-rf"] != keepBadName {
		t.Errorf("kept: %v", k)
	}
	// Duplicates and empty names do not confuse the count.
	plan = planAdmins([]posture.AdminAccount{acct("bob"), acct("bob"), {Name: ""}, acct("alice")}, []string{"alice"}, "", nil)
	if !reflect.DeepEqual(names(plan.Remove), []string{"bob"}) {
		t.Errorf("duplicates: %+v", plan)
	}
}

func TestLocalAdminsCheck(t *testing.T) {
	root := posture.AdminAccount{Name: "root", Builtin: true, Primary: true}
	acct := func(name string) posture.AdminAccount {
		return posture.AdminAccount{Name: name, Groups: []string{"sudo"}}
	}
	allowed := func(list ...any) map[string]any {
		if list == nil {
			list = []any{} // JSON [] (a nil slice would travel as null, which is refused)
		}
		return map[string]any{"allowed": list}
	}

	// Compliant.
	r := newRig(t)
	r.src.admins = []posture.AdminAccount{root, acct("alice")}
	expect(t, r.one(CheckLocalAdmins, allowed("alice"), true), true, false, "administrators: alice, root")
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}

	// Extra administrators, report only.
	r = newRig(t)
	r.src.admins = []posture.AdminAccount{root, acct("alice"), acct("bob"), acct("mallory")}
	expect(t, r.one(CheckLocalAdmins, allowed("alice"), false), false, false, "unexpected administrators: bob, mallory")
	if len(r.be.calls) != 0 || len(r.src.admins) != 4 {
		t.Errorf("changed without remediate: %v", r.be.calls)
	}

	// Remediation removes exactly the extras and lists them.
	got := r.one(CheckLocalAdmins, allowed("alice"), true)
	expect(t, got, true, true, "removed from the administrators group (accounts not deleted): bob, mallory")
	if !reflect.DeepEqual(r.be.calls, []string{"removeAdmin bob", "removeAdmin mallory"}) {
		t.Errorf("calls: %v", r.be.calls)
	}
	if !reflect.DeepEqual(names(r.src.admins), []string{"root", "alice"}) {
		t.Errorf("admins after: %v", names(r.src.admins))
	}
	logs := r.remediationLogs()
	if len(logs) != 1 || logs[0]["before"] != "administrators: alice, bob, mallory, root" || logs[0]["after"] != "administrators: alice, root" ||
		!strings.Contains(fmt.Sprint(logs[0]["action"]), "bob, mallory") || logs[0]["compliant_after"] != true {
		t.Errorf("log: %v", logs)
	}

	// Guard rails end to end: built-in, own account and the last
	// administrator stay; the device remains not compliant and says why.
	r = newRig(t)
	r.be.self = "agentsvc"
	r.src.admins = []posture.AdminAccount{root, acct("agentsvc"), acct("bob"), acct("carol")}
	got = r.one(CheckLocalAdmins, allowed(), true)
	expect(t, got, false, false, "removed from the administrators group (accounts not deleted): bob, carol",
		"kept: agentsvc (the account the agent runs as)", "still unexpected: agentsvc")
	if !reflect.DeepEqual(r.be.calls, []string{"removeAdmin bob", "removeAdmin carol"}) {
		t.Errorf("calls: %v", r.be.calls)
	}
	r = newRig(t)
	r.src.admins = []posture.AdminAccount{root, acct("bob"), acct("carol")}
	got = r.one(CheckLocalAdmins, allowed("itadmin"), true)
	expect(t, got, false, false, "removed from the administrators group (accounts not deleted): bob", "kept: carol (last remaining administrator)")
	if !reflect.DeepEqual(r.be.calls, []string{"removeAdmin bob"}) {
		t.Errorf("calls: %v", r.be.calls)
	}
	for _, call := range r.be.calls {
		if strings.Contains(call, "root") {
			t.Errorf("root was touched: %v", r.be.calls)
		}
	}
	// Only the last administrator is unexpected: nothing is removed at all.
	r = newRig(t)
	r.src.admins = []posture.AdminAccount{root, acct("bob")}
	expect(t, r.one(CheckLocalAdmins, allowed(), true), false, false, "removed from the administrators group (accounts not deleted): none", "kept: bob (last remaining administrator)")
	if len(r.be.calls) != 0 {
		t.Errorf("calls: %v", r.be.calls)
	}

	// A removal fails: reported, not compliant.
	r = newRig(t)
	r.src.admins = []posture.AdminAccount{root, acct("alice"), acct("bob")}
	r.be.failing["removeAdmin"] = errors.New("gpasswd: exit code 3")
	expect(t, r.one(CheckLocalAdmins, allowed("alice"), true), false, false, "could not remove: bob (gpasswd: exit code 3)", "still unexpected: bob")

	// Unusual names already on the device never reach a tool.
	r = newRig(t)
	r.src.admins = []posture.AdminAccount{root, acct("alice"), acct("bob; rm -rf /"), acct("$(id)")}
	got = r.one(CheckLocalAdmins, allowed("alice"), true)
	expect(t, got, false, false, "unusual account name; remove it manually")
	if len(r.be.calls) != 0 {
		t.Errorf("an unusual name reached the backend: %v", r.be.calls)
	}

	// The administrators cannot be read.
	r = newRig(t)
	r.src.adminsErr = posture.Unsupportedf("the members of the local Administrators group are not readable")
	if got := r.one(CheckLocalAdmins, allowed("alice"), true); !strings.HasPrefix(got.Detail, DetailUnsupportedPrefix) {
		t.Errorf("%+v", got)
	}
}

// TestLocalAdminsParamValidation: a bad allowed list means nothing is read
// and nothing is removed - including injection attempts in account names.
func TestLocalAdminsParamValidation(t *testing.T) {
	bad := []map[string]any{
		nil,
		{},
		{"allowed": nil},
		{"allowed": "alice"},
		{"allowed": map[string]any{"0": "alice"}},
		{"allowed": []any{"alice", 7.0}},
		{"allowed": []any{"alice", nil}},
		{"allowed": []any{"alice", []any{"bob"}}},
		{"allowed": []any{"alice", ""}},
		{"allowed": []any{"bob; rm -rf /"}},
		{"allowed": []any{"alice", "$(id)"}},
		{"allowed": []any{"alice", "`reboot`"}},
		{"allowed": []any{"alice", "-rf"}},
		{"allowed": []any{"alice", "bob\nmallory"}},
		{"allowed": []any{"alice", "../../etc/shadow"}},
		{"allowed": []any{"alice", strings.Repeat("a", 300)}},
		{"allowed": make([]any, MaxAllowedAdmins+1)},
	}
	for i := range bad[len(bad)-1]["allowed"].([]any) {
		bad[len(bad)-1]["allowed"].([]any)[i] = fmt.Sprintf("user%d", i)
	}
	for _, params := range bad {
		r := newRig(t)
		r.src.admins = []posture.AdminAccount{{Name: "root", Builtin: true}, {Name: "alice", Groups: []string{"sudo"}}, {Name: "mallory", Groups: []string{"sudo"}}}
		got := r.one(CheckLocalAdmins, params, true)
		if !strings.HasPrefix(got.Detail, DetailInvalidPrefix) || got.Compliant || got.Remediated {
			t.Errorf("%.80v: %+v", params, got)
		}
		if len(r.be.calls) != 0 || len(r.src.admins) != 3 {
			t.Errorf("%.80v: something was removed: %v", params, r.be.calls)
		}
		// The rejected value is never echoed (it may be hostile text).
		for _, hostile := range []string{"rm -rf", "$(id)", "reboot", "shadow"} {
			if strings.Contains(got.Detail, hostile) {
				t.Errorf("detail echoes the rejected value: %s", got.Detail)
			}
		}
	}
	// An empty list is valid: nobody but the built-in administrator is allowed.
	r := newRig(t)
	r.src.admins = []posture.AdminAccount{{Name: "root", Builtin: true}}
	expect(t, r.one(CheckLocalAdmins, map[string]any{"allowed": []any{}}, true), true, false)
	// The largest permitted list is accepted.
	full := make([]any, MaxAllowedAdmins)
	for i := range full {
		full[i] = fmt.Sprintf("user%d", i)
	}
	expect(t, r.one(CheckLocalAdmins, map[string]any{"allowed": full}, false), true, false)
}
