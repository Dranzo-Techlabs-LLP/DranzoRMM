//go:build windows

package netscan

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

func readNeighbors(ctx context.Context, p platform.Platform) ([]Neighbor, error) {
	out, err := posture.Exec{Platform: p}.Output(ctx, posture.PowerShell(PSNeighbors))
	if err != nil {
		return nil, err
	}
	return ParseWindowsNeighbors([]byte(out)), nil
}

// DefaultGateway returns the IPv4 default gateway, or "".
func DefaultGateway(ctx context.Context, p platform.Platform) string {
	out, err := posture.Exec{Platform: p}.Output(ctx, posture.PowerShell(PSGateway))
	if err != nil {
		return ""
	}
	return ParseWindowsGateway(out)
}

// ReadWiFi returns the active Wi-Fi connection. Windows 11 24H2+ hides the
// SSID from services unless location access is allowed; it is then "".
func ReadWiFi(ctx context.Context, p platform.Platform) (WiFi, bool) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	out, err := posture.Exec{Platform: p}.Output(ctx, posture.Cmd{
		Path: filepath.Join(root, "System32", "netsh.exe"), Args: []string{"wlan", "show", "interfaces"}, Timeout: 15 * time.Second,
	})
	if err != nil {
		return WiFi{}, false
	}
	return ParseNetshWlan(out)
}
