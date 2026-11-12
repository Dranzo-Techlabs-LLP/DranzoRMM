//go:build windows

package inventory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// cimQuery reads the hardware identity through CIM (WMI). It is a fixed
// command; nothing from the server is interpolated into it.
const cimQuery = `$ErrorActionPreference='Stop';` +
	`$b=Get-CimInstance -ClassName Win32_BIOS;` +
	`$c=Get-CimInstance -ClassName Win32_ComputerSystem;` +
	`[pscustomobject]@{serial=$b.SerialNumber;manufacturer=$c.Manufacturer;model=$c.Model}|ConvertTo-Json -Compress`

func regString(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

func hardwareFromCIM(ctx context.Context) (Hardware, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", cimQuery)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return Hardware{}, err
	}
	return ParseWindowsHardwareJSON(out)
}

func gatherOSFacts(ctx context.Context, needHardware bool) osFacts {
	var f osFacts

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		ubr, _, _ := k.GetIntegerValue("UBR")
		info := WindowsOSInfo(regString(k, "ProductName"), regString(k, "DisplayVersion"), regString(k, "ReleaseId"), regString(k, "CurrentBuildNumber"), ubr)
		_ = k.Close()
		f.OS = &info
	}

	if needHardware {
		hw, err := hardwareFromCIM(ctx)
		if err != nil || (hw.Manufacturer == "" && hw.Model == "") {
			// Registry fallback (no serial number there).
			if k, kerr := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE); kerr == nil {
				if hw.Manufacturer == "" {
					hw.Manufacturer = CleanHardwareString(regString(k, "SystemManufacturer"))
				}
				if hw.Model == "" {
					hw.Model = CleanHardwareString(regString(k, "SystemProductName"))
				}
				_ = k.Close()
			}
		}
		f.Hardware = hw
		if hw.Serial == "" {
			f.Missing = append(f.Missing, "serial")
		}
	}

	// Windows time zone key name (e.g. "W. Europe Standard Time").
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE); err == nil {
		f.Timezone = regString(k, "TimeZoneKeyName")
		_ = k.Close()
	}
	if f.Timezone == "" {
		f.Timezone, _ = time.Now().Zone()
	}
	return f
}
