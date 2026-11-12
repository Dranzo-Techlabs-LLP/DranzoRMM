package policy

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// wire records what the job manager sends to the server.
type wire struct {
	mu   sync.Mutex
	msgs []any
}

func (w *wire) Send(_ context.Context, _ string, payload any) error {
	w.mu.Lock()
	w.msgs = append(w.msgs, payload)
	w.mu.Unlock()
	return nil
}

func (w *wire) result(t *testing.T) protocol.JobResult {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		for _, m := range w.msgs {
			if res, ok := m.(protocol.JobResult); ok {
				w.mu.Unlock()
				return res
			}
		}
		w.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no job.result")
	return protocol.JobResult{}
}

// TestThroughJobManager dispatches policy.evaluate the way the agent does
// and checks the wire format of PROTOCOL.md section 6.2: job.ack, a line of
// job.output per check and one job.result whose "result" is
// {results: [{policyId, check, compliant, remediated, detail}]}.
func TestThroughJobManager(t *testing.T) {
	r := newRig(t)
	r.src.fw = &protocol.FirewallState{Enabled: false, Detail: "off"}
	w := &wire{}
	m := jobs.NewManager(context.Background(), jobs.Options{
		Sender: w, Platform: &platform.Fake{}, TempDir: t.TempDir(), FlushInterval: 5 * time.Millisecond,
	})
	defer m.Shutdown(5 * time.Second)
	m.Register(protocol.KindPolicyEvaluate, r.h)

	spec := `{"checks":[
		{"policyId":"3f0c2a8e-1111-4222-8333-444455556666","check":"firewall.enabled","params":{},"remediate":true},
		{"policyId":"3f0c2a8e-1111-4222-8333-444455557777","check":"usb.storage.blocked","params":null,"remediate":false},
		{"policyId":"3f0c2a8e-1111-4222-8333-444455558888","check":"no.such.check","remediate":true,"futureField":1}
	]}`
	r.be.usbErr = posture.Unsupportedf("usb.storage.blocked is available on Windows only")
	id := "9b2f6c1e-aaaa-4bbb-8ccc-ddddeeeeffff"
	if err := m.Dispatch(context.Background(), protocol.JobDispatch{JobRunID: id, Kind: protocol.KindPolicyEvaluate, TimeoutSeconds: 60, Spec: json.RawMessage(spec)}); err != nil {
		t.Fatal(err)
	}
	res := w.result(t)
	if res.JobRunID != id || res.Status != protocol.StatusSucceeded || res.OutputBytes == 0 {
		t.Fatalf("job.result: %+v", res)
	}
	raw, err := json.Marshal(res.Result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || len(decoded.Results) != 3 {
		t.Fatalf("result: %s (%v)", raw, err)
	}
	for _, item := range decoded.Results {
		keys := make([]string, 0, len(item))
		for k := range item {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "check,compliant,detail,policyId,remediated" {
			t.Errorf("fields of a result: %v", keys)
		}
	}
	want := []struct {
		compliant, remediated bool
		detail                string
	}{
		{true, true, "was off; did enableFirewall; firewall is on (fake: on)"},
		{false, false, "not supported on this OS: usb.storage.blocked is available on Windows only"},
		{false, false, "unknown check"},
	}
	for i, wnt := range want {
		got := decoded.Results[i]
		if got["compliant"] != wnt.compliant || got["remediated"] != wnt.remediated || got["detail"] != wnt.detail {
			t.Errorf("result %d: %v", i, got)
		}
	}
	// Acknowledged, and one output line per check.
	var acked bool
	var output strings.Builder
	w.mu.Lock()
	for _, msg := range w.msgs {
		switch v := msg.(type) {
		case protocol.JobAck:
			acked = v.Accepted && v.JobRunID == id
		case protocol.JobOutput:
			output.WriteString(v.Data)
		}
	}
	w.mu.Unlock()
	if !acked || strings.Count(output.String(), "\n") != 3 || !strings.Contains(output.String(), "firewall.enabled [3f0c2a8e-1111-4222-8333-444455556666]: REMEDIATED") {
		t.Errorf("ack=%v output=%q", acked, output.String())
	}
}

// TestNewUsesNativeBackend: the production constructor on this OS, with
// every command failing. Checks that cannot read their state report it and
// change nothing.
func TestNewUsesNativeBackend(t *testing.T) {
	var ran []string
	plat := &platform.Fake{
		ConsoleErr: platform.ErrNoConsoleUser,
		RunFunc: func(_ context.Context, cmd platform.Command) (int, error) {
			ran = append(ran, cmd.Path+" "+strings.Join(cmd.Args, " "))
			return platform.ExitCodeUnknown, errors.New("commands are disabled in this test")
		},
	}
	h := New(posture.New(plat, nil), plat)
	r := newRig(t)
	r.h = h
	results := r.run(
		protocol.PolicyCheck{PolicyID: "1", Check: CheckFirewall, Remediate: true},
		protocol.PolicyCheck{PolicyID: "2", Check: CheckLocalAdmins, Params: map[string]any{"allowed": []any{"nobody-at-all"}}, Remediate: true},
		protocol.PolicyCheck{PolicyID: "3", Check: CheckScreenLock, Params: map[string]any{"maxSeconds": 300.0}, Remediate: true},
		protocol.PolicyCheck{PolicyID: "4", Check: "bogus", Remediate: true},
	)
	for _, res := range results[:3] {
		if res.Remediated {
			t.Errorf("%s reported a remediation although no command can run: %+v", res.Check, res)
		}
	}
	if results[3].Detail != DetailUnknownCheck {
		t.Errorf("%+v", results[3])
	}
	// No command that changes something was even attempted for a state
	// that could not be read.
	for _, cmd := range ran {
		for _, write := range []string{"--setglobalstate", "dseditgroup", "gpasswd", "--force enable", "enable --now", "Set-", "Remove-"} {
			if strings.Contains(cmd, write) {
				t.Errorf("a changing command was attempted: %s", cmd)
			}
		}
	}
}
