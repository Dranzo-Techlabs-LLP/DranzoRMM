//go:build windows

package pkginstall

import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

func defaultEnv(platform.Platform) Env {
	return Env{
		OSName:         "Windows",
		Types:          []string{TypeMSI, TypeEXE},
		Detections:     []string{DetectFile, DetectRegistry, DetectWinget},
		UninstallTools: []string{"msiexec", "winget"},
		Lookup:         software.LookupTool,
		FileVersion:    fileVersion,
		Registry:       registryDetect,
	}
}

// maxVersionInfoBytes bounds the version resource read from a file.
const maxVersionInfoBytes = 4 << 20

// fileVersion returns the file version ("a.b.c.d") from the file's version
// resource, or "" when it has none.
func fileVersion(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 || size > maxVersionInfoBytes {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil { //nolint:gosec // documented Win32 API; buf is sized by GetFileVersionInfoSize
		return ""
	}
	var info *windows.VS_FIXEDFILEINFO
	var infoLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&info), &infoLen); err != nil { //nolint:gosec // documented Win32 API; the returned length is checked below
		return ""
	}
	if info == nil || infoLen < uint32(unsafe.Sizeof(*info)) || info.Signature != 0xFEEF04BD {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		info.FileVersionMS>>16, info.FileVersionMS&0xFFFF,
		info.FileVersionLS>>16, info.FileVersionLS&0xFFFF)
}

// registryDetect evaluates a registry rule on a key below HKLM, in the
// 64-bit view first and then in the 32-bit (WOW6432Node) view. Without a
// value name the key's existence means "installed" and its DisplayVersion,
// if any, is the version; with a value name that value must exist and its
// content is the version.
func registryDetect(sub, valueName string) (software.PackageState, error) {
	var lastErr error
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, sub, registry.QUERY_VALUE|view)
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				lastErr = err
			}
			continue
		}
		name := valueName
		if name == "" {
			name = "DisplayVersion"
		}
		version, found := "", false
		if s, _, err := k.GetStringValue(name); err == nil {
			version, found = s, true
		} else if n, _, err := k.GetIntegerValue(name); err == nil {
			version, found = strconv.FormatUint(n, 10), true
		}
		_ = k.Close()
		if valueName != "" && !found {
			continue
		}
		return software.PackageState{Installed: true, Version: software.Clean(version, 128)}, nil
	}
	return software.PackageState{}, lastErr
}
