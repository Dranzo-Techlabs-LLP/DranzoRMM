//go:build linux

package netscan

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

func readSmallFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	return string(b), err
}

func readNeighbors(context.Context, platform.Platform) ([]Neighbor, error) {
	out, err := readSmallFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	return ParseProcNetArp(out), nil
}

// DefaultGateway returns the IPv4 default gateway, or "".
func DefaultGateway(context.Context, platform.Platform) string {
	out, err := readSmallFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return ParseProcNetRoute(out)
}

// ReadWiFi returns the active Wi-Fi connection through NetworkManager, when installed.
func ReadWiFi(ctx context.Context, p platform.Platform) (WiFi, bool) {
	nmcli := posture.LookTool("nmcli")
	if nmcli == "" {
		return WiFi{}, false
	}
	out, err := posture.Exec{Platform: p}.Output(ctx, posture.Cmd{
		Path: nmcli, Args: []string{"-t", "-f", "ACTIVE,SSID,BSSID,DEVICE", "dev", "wifi", "list", "--rescan", "no"},
		Env: []string{"LC_ALL=C"}, Timeout: 10 * time.Second,
	})
	if err != nil {
		return WiFi{}, false
	}
	return ParseNmcliWifi(out)
}
