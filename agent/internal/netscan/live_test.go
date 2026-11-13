package netscan

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// TestLiveScan scans the real local network. Opt-in: DRANZO_LIVE_NETSCAN=1.
func TestLiveScan(t *testing.T) {
	if os.Getenv("DRANZO_LIVE_NETSCAN") != "1" {
		t.Skip("set DRANZO_LIVE_NETSCAN=1 to scan the local network")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p := platform.New()
	res, err := New(p).Run(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("subnets %v gateway %q neighbors %d truncated %v", res.Subnets, res.Gateway, len(res.Neighbors), res.Truncated)
	for _, n := range res.Neighbors {
		t.Logf("  %-15s %s gw=%v rnd=%v %s", n.IP, n.MAC, n.Gateway, n.Randomized, n.Hostname)
	}
	w, ok := ReadWiFi(ctx, p)
	t.Logf("wifi %+v ok=%v", w, ok)
}
