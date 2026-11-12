//go:build linux

package software_test

import (
	"context"
	"os"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// TestRealLinuxInventory runs the real collectors (opt-in, used in the
// Debian and Rocky Linux test containers).
func TestRealLinuxInventory(t *testing.T) {
	if os.Getenv("DRANZO_REAL_LINUX") != "1" {
		t.Skip("set DRANZO_REAL_LINUX=1 to run the collectors on this system")
	}
	inv := software.NewCollector(platform.New()).Collect(context.Background())
	count := map[string]int{}
	var bash *protocol.SoftwareItem
	for i, it := range inv.Items {
		count[it.Source]++
		if it.Name == "bash" {
			bash = &inv.Items[i]
		}
		if it.Name == "" || it.Version == "" || it.ID == "" {
			t.Fatalf("incomplete item: %+v", it)
		}
	}
	t.Logf("items: %d (%v), unsupported=%v", len(inv.Items), count, inv.Unsupported)
	if bash != nil {
		t.Logf("bash: %+v", *bash)
	}
	if len(inv.Items) < 50 || bash == nil {
		t.Fatalf("expected the system's packages including bash, got %d items", len(inv.Items))
	}
	want := os.Getenv("DRANZO_EXPECT_SOURCE")
	if want != "" && (bash.Source != want || count[want] < 50) {
		t.Fatalf("expected source %s, got %v", want, count)
	}
	if len(inv.Unsupported) != 0 {
		t.Fatalf("unsupported = %v", inv.Unsupported)
	}
}
