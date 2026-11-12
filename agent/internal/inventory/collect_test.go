package inventory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// TestCollectOnHost runs the real collector of the host OS with a fake
// platform handle and checks the shape of the report.
func TestCollectOnHost(t *testing.T) {
	fake := &platform.Fake{ID: "machine-1", User: &platform.User{Name: "alice"}, Users: []string{"alice", "bob"}, Reboot: true}
	c := NewCollector(fake, "1.2.3")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	inv := c.Collect(ctx)

	if inv.Hostname == "" || inv.MachineID != "machine-1" || inv.Arch == "" {
		t.Fatalf("identity fields: %+v", inv)
	}
	if inv.OS == nil || inv.OS.Family != platform.OSFamily || inv.OS.Name == "" {
		t.Fatalf("os: %+v", inv.OS)
	}
	if inv.CPU == nil || inv.CPU.LogicalCores < 1 {
		t.Fatalf("cpu: %+v", inv.CPU)
	}
	if inv.MemoryBytes == 0 {
		t.Fatal("memory not collected")
	}
	if len(inv.Disks) == 0 {
		t.Fatal("no disks")
	}
	for _, d := range inv.Disks {
		if d.TotalBytes == 0 || d.FreeBytes > d.TotalBytes || d.MountPoint == "" {
			t.Fatalf("disk: %+v", d)
		}
	}
	if inv.ConsoleUser != "alice" || len(inv.LoggedInUsers) != 2 || !inv.PendingReboot {
		t.Fatalf("user / reboot fields: %+v", inv)
	}
	if inv.BootTime == nil || inv.UptimeSeconds == 0 || inv.Timezone == "" {
		t.Fatalf("time fields: boot=%v uptime=%d tz=%q", inv.BootTime, inv.UptimeSeconds, inv.Timezone)
	}
	if inv.Agent == nil || inv.Agent.Version != "1.2.3" || inv.Agent.RSSBytes == 0 {
		t.Fatalf("agent stats: %+v", inv.Agent)
	}
	for _, n := range inv.Network {
		if n.Name == "" || len(n.IPv4)+len(n.IPv6) == 0 {
			t.Fatalf("nic: %+v", n)
		}
	}
	// The payload uses the documented JSON names and never null lists.
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, key := range []string{"collectedAt", "hostname", "machineId", "os", "arch", "cpu", "memoryBytes", "disks", "network",
		"serial", "manufacturer", "model", "consoleUser", "loggedInUsers", "bootTime", "uptimeSeconds", "pendingReboot",
		"timezone", "agent", "unsupported"} {
		if _, ok := m[key]; !ok {
			t.Errorf("payload lacks %q", key)
		}
	}
	for _, key := range []string{"disks", "network", "loggedInUsers", "unsupported"} {
		if m[key] == nil {
			t.Errorf("%q must be a list, not null", key)
		}
	}

	hb := c.SystemStats(ctx)
	if hb.UptimeSeconds == 0 || hb.MemUsedPercent <= 0 || hb.MemUsedPercent > 100 {
		t.Fatalf("system stats: %+v", hb)
	}
	if _, rss := c.SelfStats(ctx); rss == 0 {
		t.Fatal("self RSS not collected")
	}
}
