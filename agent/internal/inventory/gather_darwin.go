//go:build darwin

package inventory

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/shirou/gopsutil/v4/host"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func run(ctx context.Context, timeout time.Duration, path string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	cmd.WaitDelay = time.Second
	return cmd.Output()
}

func gatherOSFacts(ctx context.Context, needHardware bool) osFacts {
	var f osFacts

	kernel, _ := host.KernelVersionWithContext(ctx)
	if out, err := run(ctx, 10*time.Second, "/usr/bin/sw_vers"); err == nil {
		name, version, build := ParseSwVers(string(out))
		f.OS = &protocol.OSInfo{Family: protocol.OSMacOS, Name: name, Version: version, Build: build, Kernel: kernel}
	}

	if needHardware {
		if out, err := run(ctx, 30*time.Second, "/usr/sbin/system_profiler", "SPHardwareDataType", "-json"); err == nil {
			if hw, err := ParseSystemProfilerHardware(out); err == nil {
				f.Hardware = hw
			}
		}
		if f.Hardware.Serial == "" {
			if out, err := run(ctx, 10*time.Second, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
				f.Hardware.Serial = CleanHardwareString(platform.ParseIoregValue(string(out), "IOPlatformSerialNumber"))
				if f.Hardware.Manufacturer == "" {
					f.Hardware.Manufacturer = "Apple Inc."
				}
			}
		}
		if f.Hardware.Serial == "" {
			f.Missing = append(f.Missing, "serial")
		}
	}

	if target, err := os.Readlink("/etc/localtime"); err == nil {
		f.Timezone = TimezoneFromLink(target)
	}
	if f.Timezone == "" {
		f.Timezone, _ = time.Now().Zone()
	}
	return f
}
