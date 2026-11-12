//go:build windows

package files

import "testing"

func specialFiles(*testing.T, string) map[string]string { return map[string]string{} }

func TestDevicePathsRefused(t *testing.T) {
	for _, p := range []string{`\\.\PhysicalDrive0`, `\\.\pipe\x`, `\\?\GLOBALROOT\Device\Null`, `//./C:`} {
		if _, err := ValidatePath(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}
