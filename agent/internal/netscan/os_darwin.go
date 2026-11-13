//go:build darwin

package netscan

import (
	"context"
	"errors"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

func readNeighbors(ctx context.Context, p platform.Platform) ([]Neighbor, error) {
	arp := posture.LookTool("arp")
	if arp == "" {
		return nil, errors.New("arp not found")
	}
	out, err := posture.Exec{Platform: p}.Output(ctx, posture.Cmd{Path: arp, Args: []string{"-an"}, Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	return ParseDarwinArp(out), nil
}

// DefaultGateway returns the IPv4 default gateway, or "".
func DefaultGateway(ctx context.Context, p platform.Platform) string {
	route := posture.LookTool("route")
	if route == "" {
		return ""
	}
	out, err := posture.Exec{Platform: p}.Output(ctx, posture.Cmd{Path: route, Args: []string{"-n", "get", "default"}, Timeout: 10 * time.Second})
	if err != nil {
		return ""
	}
	return ParseDarwinRouteGet(out)
}

// ReadWiFi returns the active Wi-Fi connection. macOS 14+ hides the SSID from
// processes without location permission; it is then "".
func ReadWiFi(ctx context.Context, p platform.Platform) (WiFi, bool) {
	ipconfig := posture.LookTool("ipconfig")
	if ipconfig == "" {
		return WiFi{}, false
	}
	for _, ifc := range []string{"en0", "en1", "en2"} {
		out, err := posture.Exec{Platform: p}.Output(ctx, posture.Cmd{Path: ipconfig, Args: []string{"getsummary", ifc}, Timeout: 10 * time.Second})
		if err != nil {
			continue
		}
		if w, ok := ParseDarwinSummary(ifc, out); ok {
			return w, true
		}
	}
	return WiFi{}, false
}
