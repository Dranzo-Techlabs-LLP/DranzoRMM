//go:build windows

package software

import (
	"context"

	"golang.org/x/sys/windows/registry"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// maxUninstallSubkeys bounds the registry enumeration of one view.
const maxUninstallSubkeys = 20000

func regString(k registry.Key, name string) string {
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return s
}

// readUninstallView reads the uninstall entries of one registry view
// (registry.WOW64_64KEY or registry.WOW64_32KEY; the 32-bit view is the
// WOW6432Node key).
func readUninstallView(view uint32, label string) ([]RegistryEntry, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|view)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	names, err := root.ReadSubKeyNames(maxUninstallSubkeys)
	if err != nil && len(names) == 0 {
		return nil, err
	}
	entries := make([]RegistryEntry, 0, len(names))
	for _, name := range names {
		k, err := registry.OpenKey(root, name, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		e := RegistryEntry{
			Key:            name,
			View:           label,
			DisplayName:    regString(k, "DisplayName"),
			DisplayVersion: regString(k, "DisplayVersion"),
			Publisher:      regString(k, "Publisher"),
			InstallDate:    regString(k, "InstallDate"),
			ParentKeyName:  regString(k, "ParentKeyName"),
			ReleaseType:    regString(k, "ReleaseType"),
		}
		if v, _, err := k.GetIntegerValue("SystemComponent"); err == nil {
			e.SystemComponent = v
		}
		_ = k.Close()
		entries = append(entries, e)
	}
	return entries, nil
}

// gatherOS reads the HKLM uninstall keys (64-bit and 32-bit views) and, when
// winget is usable, the packages only winget knows about.
func gatherOS(ctx context.Context, plat platform.Platform) (items []protocol.SoftwareItem, unsupported []string) {
	var entries []RegistryEntry
	native, errNative := readUninstallView(registry.WOW64_64KEY, "64")
	entries = append(entries, native...)
	// On 32-bit Windows both views are the same key; RegistryItems' caller
	// de-duplicates, so reading it twice is harmless.
	wow, errWow := readUninstallView(registry.WOW64_32KEY, "32")
	entries = append(entries, wow...)
	if errNative != nil && errWow != nil {
		unsupported = append(unsupported, protocol.SourceRegistry)
	}
	items = append(items, RegistryItems(entries)...)

	if w, ok := GatherWinget(ctx, plat, LookupTool("winget")); ok {
		items = append(items, w...)
	} else {
		unsupported = append(unsupported, protocol.SourceWinget)
	}
	return items, unsupported
}
