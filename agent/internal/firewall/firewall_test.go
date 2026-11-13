package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func mustRules(t *testing.T, js string) []Rule {
	t.Helper()
	var raw any
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		t.Fatal(err)
	}
	r, err := ParseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseRulesNormalizesAndValidates(t *testing.T) {
	r := mustRules(t, `[{"name":"Block SMB","direction":"IN","action":"block","protocol":"TCP","ports":["445"," 139","445"],"remoteAddresses":["10.0.0.5","192.168.1.77/24"]}]`)[0]
	if r.Direction != "in" || r.Protocol != "tcp" || strings.Join(r.Ports, ",") != "139,445" || strings.Join(r.RemoteAddresses, ",") != "10.0.0.5/32,192.168.1.0/24" {
		t.Errorf("normalized %+v", r)
	}
	bad := map[string]string{
		"no name":                   `[{"name":"","direction":"in","action":"block","protocol":"tcp","ports":["1"]}]`,
		"injection in name":         `[{"name":"x\"; drop","direction":"in","action":"block","protocol":"tcp"}]`,
		"bad direction":             `[{"name":"a","direction":"both","action":"block","protocol":"tcp"}]`,
		"ports without protocol":    `[{"name":"a","direction":"in","action":"block","protocol":"any","ports":["80"]}]`,
		"port range reversed":       `[{"name":"a","direction":"in","action":"block","protocol":"tcp","ports":["90-80"]}]`,
		"port out of range":         `[{"name":"a","direction":"in","action":"block","protocol":"tcp","ports":["70000"]}]`,
		"bad address":               `[{"name":"a","direction":"in","action":"block","protocol":"tcp","remoteAddresses":["10.0.0.0/33"]}]`,
		"relative program":          `[{"name":"a","direction":"out","action":"block","protocol":"any","program":"app.exe"}]`,
		"block everything outgoing": `[{"name":"a","direction":"out","action":"block","protocol":"any"}]`,
		"not a list":                `{"name":"a"}`,
	}
	for name, js := range bad {
		var raw any
		_ = json.Unmarshal([]byte(js), &raw)
		if _, err := ParseRules(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseRules(nil); err == nil {
		t.Error("missing rules accepted")
	}
	many := make([]any, MaxRules+1)
	for i := range many {
		many[i] = map[string]any{"name": "r", "direction": "in", "action": "allow", "protocol": "tcp"}
	}
	if _, err := ParseRules(many); err == nil {
		t.Error("too many rules accepted")
	}
}

func TestIDIsStableAndContentBased(t *testing.T) {
	a := mustRules(t, `[{"name":"A","direction":"in","action":"block","protocol":"tcp","ports":["445","139"]}]`)[0]
	b := mustRules(t, `[{"name":"A","direction":"in","action":"block","protocol":"tcp","ports":["139","445"]}]`)[0]
	c := mustRules(t, `[{"name":"A","direction":"in","action":"allow","protocol":"tcp","ports":["139","445"]}]`)[0]
	if a.ID() != b.ID() || a.ID() == c.ID() || len(a.ID()) != 16 {
		t.Errorf("ids %s %s %s", a.ID(), b.ID(), c.ID())
	}
}

func TestApplicableAndDiff(t *testing.T) {
	rules := mustRules(t, `[
		{"name":"SMB","direction":"in","action":"block","protocol":"tcp","ports":["445"]},
		{"name":"SMB","direction":"in","action":"block","protocol":"tcp","ports":["445"]},
		{"name":"No torrent","direction":"out","action":"block","protocol":"any","program":"C:\\Apps\\torrent.exe"}]`)
	unix, skipped := Applicable(rules, false)
	if len(unix) != 1 || len(skipped) != 1 || skipped[0] != "No torrent" {
		t.Errorf("unix %v skipped %v", unix, skipped)
	}
	win, _ := Applicable(rules, true)
	if len(win) != 2 {
		t.Errorf("windows %v", win)
	}
	missing, unexpected := Diff([]string{"0000000000000000", win[0].ID()}, win)
	if len(missing) != 1 || missing[0].Name != "No torrent" || len(unexpected) != 1 {
		t.Errorf("missing %v unexpected %v", missing, unexpected)
	}
}

const nftRules = `[
	{"name":"Block SMB","direction":"in","action":"block","protocol":"tcp","ports":["139","445"],"remoteAddresses":["10.0.0.0/8","fd00::/8"]},
	{"name":"Allow DNS","direction":"out","action":"allow","protocol":"udp","ports":["53"]},
	{"name":"Block host","direction":"out","action":"block","protocol":"any","remoteAddresses":["203.0.113.9"]}]`

func TestRenderNft(t *testing.T) {
	rules := mustRules(t, nftRules)
	got := RenderNft(rules)
	want := "add table inet dranzormm\ndelete table inet dranzormm\ntable inet dranzormm {\n" +
		"\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n" +
		"\t\tip saddr { 10.0.0.0/8 } tcp dport { 139, 445 } counter drop comment \"dranzo:" + rules[0].ID() + "\"\n" +
		"\t\tip6 saddr { fd00::/8 } tcp dport { 139, 445 } counter drop comment \"dranzo:" + rules[0].ID() + "\"\n" +
		"\t}\n\tchain output {\n\t\ttype filter hook output priority -10; policy accept;\n" +
		"\t\tudp dport { 53 } counter accept comment \"dranzo:" + rules[1].ID() + "\"\n" +
		"\t\tip daddr { 203.0.113.9/32 } counter drop comment \"dranzo:" + rules[2].ID() + "\"\n" +
		"\t}\n}\n"
	if got != want {
		t.Errorf("nft script:\n%s\nwant:\n%s", got, want)
	}
	listing := `{"nftables":[{"metainfo":{}},{"rule":{"family":"inet","table":"dranzormm","chain":"input","comment":"dranzo:` + rules[0].ID() + `"}},{"rule":{"comment":"dranzo:` + rules[0].ID() + `"}},{"rule":{"comment":"someone else"}}]}`
	if ids := ParseOwnedIDs(listing); len(ids) != 1 || ids[0] != rules[0].ID() {
		t.Errorf("owned %v", ids)
	}
}

func TestRenderPf(t *testing.T) {
	rules := mustRules(t, nftRules+``)
	rules = append(rules, mustRules(t, `[{"name":"Allow SSH range","direction":"in","action":"allow","protocol":"tcp","ports":["2200-2299"]}]`)...)
	got := RenderPf(rules)
	want := "block drop in quick inet proto tcp from { 10.0.0.0/8 } to any port { 139, 445 } label \"dranzo:" + rules[0].ID() + "\"\n" +
		"block drop in quick inet6 proto tcp from { fd00::/8 } to any port { 139, 445 } label \"dranzo:" + rules[0].ID() + "\"\n" +
		"pass out quick proto udp from any to any port { 53 } keep state label \"dranzo:" + rules[1].ID() + "\"\n" +
		"block drop out quick inet from any to { 203.0.113.9/32 } label \"dranzo:" + rules[2].ID() + "\"\n" +
		"pass in quick proto tcp from any to any port { 2200:2299 } keep state label \"dranzo:" + rules[3].ID() + "\"\n"
	if got != want {
		t.Errorf("pf rules:\n%s\nwant:\n%s", got, want)
	}
}

func TestWindowsPayloadUsesFirewallVocabulary(t *testing.T) {
	rules := mustRules(t, `[{"name":"No torrent","direction":"out","action":"block","protocol":"any","program":"C:\\Apps\\torrent.exe"},{"name":"RDP from IT","direction":"in","action":"allow","protocol":"tcp","ports":["3389"],"remoteAddresses":["10.1.0.0/16"]}]`)
	js, err := WindowsPayload(rules)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatal(err)
	}
	if got[0]["direction"] != "Outbound" || got[0]["action"] != "Block" || got[0]["protocol"] != "Any" || got[0]["program"] != `C:\Apps\torrent.exe` {
		t.Errorf("rule 1 %v", got[0])
	}
	if got[1]["direction"] != "Inbound" || got[1]["protocol"] != "TCP" || got[1]["id"] != rules[1].ID() {
		t.Errorf("rule 2 %v", got[1])
	}
	if ids := ParseOwnedIDs("dranzo:" + rules[0].ID() + "\r\ndranzo:" + rules[1].ID() + "\r\n"); len(ids) != 2 {
		t.Errorf("windows owned %v", ids)
	}
}

type fakeBackend struct {
	applied [][]Rule
	fail    error
}

func (f *fakeBackend) Owned(context.Context) ([]string, error) {
	if len(f.applied) == 0 {
		return nil, nil
	}
	var ids []string
	for _, r := range f.applied[len(f.applied)-1] {
		ids = append(ids, r.ID())
	}
	return ids, nil
}

func (f *fakeBackend) Apply(_ context.Context, rules []Rule) error {
	if f.fail != nil {
		return f.fail
	}
	f.applied = append(f.applied, rules)
	return nil
}

func TestManagerRollsBackWhenServerBecomesUnreachable(t *testing.T) {
	dir := t.TempDir()
	first := mustRules(t, `[{"name":"A","direction":"in","action":"block","protocol":"tcp","ports":["445"]}]`)
	second := mustRules(t, `[{"name":"Cut","direction":"out","action":"block","protocol":"tcp","ports":["8443"]}]`)
	be := &fakeBackend{}
	reachable := true
	m := &Manager{Backend: be, StatePath: filepath.Join(dir, "fw.json"), Reachable: func(context.Context) error {
		if reachable {
			return nil
		}
		return errors.New("timeout")
	}}
	if err := m.Enforce(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	reachable = false
	err := m.Enforce(context.Background(), second)
	if err == nil || !strings.Contains(err.Error(), "previous rules were restored") {
		t.Fatalf("err %v", err)
	}
	last := be.applied[len(be.applied)-1]
	if len(last) != 1 || last[0].ID() != first[0].ID() {
		t.Errorf("rolled back to %v", last)
	}
	// The state file still holds the rules that are in place.
	if got := m.load(); len(got) != 1 || got[0].ID() != first[0].ID() {
		t.Errorf("state %v", got)
	}
	if err := m.Clear(context.Background()); err != nil || len(be.applied[len(be.applied)-1]) != 0 || m.load() != nil {
		t.Errorf("clear: %v", err)
	}
}
