//go:build linux

package inventory

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
)

func readSmall(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > 4096 {
		data = data[:4096]
	}
	return string(data)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func gatherOSFacts(ctx context.Context, needHardware bool) osFacts {
	var f osFacts

	kernel, _ := host.KernelVersionWithContext(ctx)
	content := readSmall("/etc/os-release")
	if content == "" {
		content = readSmall("/usr/lib/os-release")
	}
	info := LinuxOSInfo(ParseOSRelease(content), kernel)
	f.OS = &info

	if needHardware {
		const dmi = "/sys/class/dmi/id/"
		f.Hardware = Hardware{
			// product_serial is readable by root only; device-tree is the ARM (non-DMI) fallback.
			Serial: firstNonEmpty(
				CleanHardwareString(readSmall(dmi+"product_serial")),
				CleanHardwareString(readSmall(dmi+"board_serial")),
				CleanHardwareString(readSmall("/sys/firmware/devicetree/base/serial-number")),
			),
			Manufacturer: firstNonEmpty(
				CleanHardwareString(readSmall(dmi+"sys_vendor")),
				CleanHardwareString(readSmall(dmi+"board_vendor")),
			),
			Model: firstNonEmpty(
				CleanHardwareString(readSmall(dmi+"product_name")),
				CleanHardwareString(readSmall(dmi+"board_name")),
				CleanHardwareString(readSmall("/sys/firmware/devicetree/base/model")),
			),
		}
		if f.Hardware.Serial == "" {
			f.Missing = append(f.Missing, "serial")
		}
	}

	if tz := strings.TrimSpace(os.Getenv("TZ")); tz != "" && !strings.HasPrefix(tz, ":") && !strings.ContainsAny(tz, " \t") {
		f.Timezone = tz
	}
	if f.Timezone == "" {
		if target, err := os.Readlink("/etc/localtime"); err == nil {
			f.Timezone = TimezoneFromLink(target)
		}
	}
	if f.Timezone == "" {
		f.Timezone = strings.TrimSpace(readSmall("/etc/timezone"))
	}
	if f.Timezone == "" {
		f.Timezone, _ = time.Now().Zone()
	}
	return f
}
