// Package inventory collects the "inventory" report (PROTOCOL.md section 7.1)
// and the live statistics used by the heartbeat.
//
// Gathering (running commands, reading files, calling OS APIs) lives in the
// per-OS gather_*.go files; all parsing lives in parse.go as pure functions.
package inventory

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/dranzo/dranzormm/agent/internal/netscan"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// osFacts is what the per-OS gatherer contributes.
type osFacts struct {
	OS       *protocol.OSInfo
	Hardware Hardware
	Timezone string
	// Missing lists the sub-sections that could not be collected.
	Missing []string
}

// Collector builds inventory reports and heartbeat statistics.
type Collector struct {
	Platform platform.Platform
	Version  string

	mu          sync.Mutex
	lastCPUTime float64
	lastSample  time.Time
	proc        *process.Process
	hw          *Hardware // hardware identity does not change while running
}

// NewCollector returns a collector for this process.
func NewCollector(p platform.Platform, version string) *Collector {
	return &Collector{Platform: p, Version: version}
}

// Arch returns the protocol architecture name of this build.
func Arch() string { return runtime.GOARCH }

// Hostname returns the host name ("" if unavailable).
func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func rawInterfaces() ([]RawInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	raw := make([]RawInterface, 0, len(ifaces))
	for _, ifc := range ifaces {
		r := RawInterface{
			Name:     ifc.Name,
			MAC:      ifc.HardwareAddr.String(),
			Loopback: ifc.Flags&net.FlagLoopback != 0,
			Up:       ifc.Flags&net.FlagUp != 0,
		}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				r.Addrs = append(r.Addrs, a.String())
			}
		}
		raw = append(raw, r)
	}
	return raw, nil
}

func disks(ctx context.Context) ([]protocol.DiskInfo, error) {
	parts, err := disk.PartitionsWithContext(ctx, true)
	if err != nil && len(parts) == 0 {
		return nil, err
	}
	in := make([]Partition, 0, len(parts))
	for _, p := range parts {
		in = append(in, Partition{Device: p.Device, MountPoint: p.Mountpoint, FSType: p.Fstype})
	}
	out := []protocol.DiskInfo{}
	for _, p := range FilterPartitions(platform.OSFamily, in) {
		u, err := disk.UsageWithContext(ctx, p.MountPoint)
		if err != nil || u.Total == 0 {
			continue
		}
		out = append(out, protocol.DiskInfo{
			Device: p.Device, MountPoint: p.MountPoint, FSType: p.FSType,
			TotalBytes: u.Total, FreeBytes: u.Free,
		})
	}
	return out, nil
}

// Collect gathers a full inventory. Sub-collectors that fail are reported in
// Unsupported instead of failing the whole report.
func (c *Collector) Collect(ctx context.Context) *protocol.Inventory {
	now := time.Now().UTC()
	inv := &protocol.Inventory{
		CollectedAt:   now,
		Hostname:      Hostname(),
		Arch:          Arch(),
		Disks:         []protocol.DiskInfo{},
		Network:       []protocol.NetworkInterface{},
		LoggedInUsers: []string{},
		Unsupported:   []string{},
	}
	miss := func(name string) { inv.Unsupported = append(inv.Unsupported, name) }

	if id, err := c.Platform.MachineID(ctx); err == nil {
		inv.MachineID = id
	} else {
		miss("machineId")
	}

	c.mu.Lock()
	cachedHW := c.hw
	c.mu.Unlock()
	facts := gatherOSFacts(ctx, cachedHW == nil)
	if cachedHW != nil {
		facts.Hardware = *cachedHW
	} else if facts.Hardware.Serial != "" {
		hw := facts.Hardware
		c.mu.Lock()
		c.hw = &hw
		c.mu.Unlock()
	}
	inv.OS = facts.OS
	if inv.OS == nil {
		miss("os")
	}
	inv.Serial, inv.Manufacturer, inv.Model = facts.Hardware.Serial, facts.Hardware.Manufacturer, facts.Hardware.Model
	inv.Timezone = facts.Timezone
	for _, m := range facts.Missing {
		miss(m)
	}

	cpuInfo := &protocol.CPUInfo{}
	if infos, err := cpu.InfoWithContext(ctx); err == nil && len(infos) > 0 {
		cpuInfo.Model = infos[0].ModelName
	}
	if n, err := cpu.CountsWithContext(ctx, false); err == nil {
		cpuInfo.Cores = n
	}
	if n, err := cpu.CountsWithContext(ctx, true); err == nil {
		cpuInfo.LogicalCores = n
	}
	if cpuInfo.LogicalCores == 0 {
		cpuInfo.LogicalCores = runtime.NumCPU()
	}
	inv.CPU = cpuInfo

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		inv.MemoryBytes = vm.Total
	} else {
		miss("memoryBytes")
	}

	if d, err := disks(ctx); err == nil {
		inv.Disks = d
	} else {
		miss("disks")
	}

	if raw, err := rawInterfaces(); err == nil {
		inv.Network = FilterInterfaces(raw)
	} else {
		miss("network")
	}

	inv.DefaultGateway = netscan.DefaultGateway(ctx, c.Platform)
	if w, ok := netscan.ReadWiFi(ctx, c.Platform); ok {
		inv.WiFi = &protocol.WiFiInfo{Interface: w.Interface, SSID: w.SSID, BSSID: w.BSSID}
	}

	if u, err := c.Platform.ConsoleUser(ctx); err == nil {
		inv.ConsoleUser = u.Name
	} else if !errors.Is(err, platform.ErrNoConsoleUser) {
		miss("consoleUser")
	}
	if users, err := c.Platform.LoggedInUsers(ctx); err == nil {
		if users != nil {
			inv.LoggedInUsers = users
		}
	} else {
		miss("loggedInUsers")
	}

	if boot, err := host.BootTimeWithContext(ctx); err == nil && boot > 0 {
		bt := time.Unix(int64(boot), 0).UTC() //nolint:gosec // boot time fits in int64
		inv.BootTime = &bt
		if now.After(bt) {
			inv.UptimeSeconds = uint64(now.Sub(bt) / time.Second) //nolint:gosec // non-negative
		}
	} else {
		miss("bootTime")
	}

	if reboot, err := c.Platform.PendingReboot(ctx); err == nil {
		inv.PendingReboot = reboot
	} else {
		miss("pendingReboot")
	}

	cpuPct, rss := c.SelfStats(ctx)
	inv.Agent = &protocol.AgentStats{Version: c.Version, CPUPercent: cpuPct, RSSBytes: rss}
	return inv
}

// SelfStats returns the agent's own CPU usage (percent of one core, averaged
// since the previous call) and resident set size.
func (c *Collector) SelfStats(ctx context.Context) (cpuPercent float64, rssBytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proc == nil {
		p, err := process.NewProcessWithContext(ctx, int32(os.Getpid())) //nolint:gosec // pid fits in int32
		if err != nil {
			return 0, 0
		}
		c.proc = p
	}
	if mi, err := c.proc.MemoryInfoWithContext(ctx); err == nil && mi != nil {
		rssBytes = mi.RSS
	}
	if t, err := c.proc.TimesWithContext(ctx); err == nil && t != nil {
		total := t.User + t.System
		now := time.Now()
		if !c.lastSample.IsZero() {
			if wall := now.Sub(c.lastSample).Seconds(); wall > 0 {
				cpuPercent = (total - c.lastCPUTime) / wall * 100
			}
		}
		c.lastCPUTime, c.lastSample = total, now
	}
	if cpuPercent < 0 {
		cpuPercent = 0
	}
	return round2(cpuPercent), rssBytes
}

// SystemStats are the host-level numbers of a heartbeat.
type SystemStats struct {
	UptimeSeconds  uint64
	CPUPercent     float64
	MemUsedPercent float64
}

// SystemStats samples host CPU (since the previous call), memory and uptime.
func (c *Collector) SystemStats(ctx context.Context) SystemStats {
	var s SystemStats
	if up, err := host.UptimeWithContext(ctx); err == nil {
		s.UptimeSeconds = up
	}
	if pct, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(pct) > 0 {
		s.CPUPercent = round2(pct[0])
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		s.MemUsedPercent = round2(vm.UsedPercent)
	}
	return s
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
