package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func testPaths(t *testing.T) Paths {
	t.Helper()
	p := ResolvePaths(filepath.Join(t.TempDir(), "data"))
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigRoundTripAndDefaults(t *testing.T) {
	p := testPaths(t)
	if _, err := Load(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist, got %v", err)
	}
	in := &Config{ServerURL: "https://rmm.example.com:8443", DeviceID: "11111111-2222-4333-8444-555555555555",
		UninstallCode: &protocol.UninstallCode{Salt: "c2FsdA==", Iterations: 600000, Hash: "aGFzaA=="}}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if out.ServerURL != in.ServerURL || out.DeviceID != in.DeviceID || out.UninstallCode == nil || out.UninstallCode.Iterations != 600000 {
		t.Fatalf("round trip: %+v", out)
	}
	if out.HeartbeatSeconds != 60 || out.MaxConcurrentJobs != 4 || out.InventoryIntervalSeconds != DefaultInventorySeconds {
		t.Fatalf("defaults not applied: %+v", out)
	}
}

func TestClampHelloAck(t *testing.T) {
	var c Config
	c.Normalize()
	changed := c.ApplyHelloAck(protocol.HelloAck{
		HeartbeatSeconds:         1,        // below 15
		InventoryIntervalSeconds: 10,       // below 5 min
		SoftwareIntervalSeconds:  99999999, // above 7 days
		PostureIntervalSeconds:   0,        // missing: keep
		PatchScanIntervalSeconds: 7200,
	})
	if !changed {
		t.Fatal("expected a change")
	}
	if c.HeartbeatSeconds != 15 || c.InventoryIntervalSeconds != 300 || c.SoftwareIntervalSeconds != 7*24*3600 ||
		c.PostureIntervalSeconds != DefaultPostureSeconds || c.PatchScanIntervalSeconds != 7200 {
		t.Fatalf("clamping wrong: %+v", c)
	}
	c.ApplyHelloAck(protocol.HelloAck{HeartbeatSeconds: 100000})
	if c.HeartbeatSeconds != 600 {
		t.Fatalf("heartbeat upper clamp: %d", c.HeartbeatSeconds)
	}
	if c.ApplyHelloAck(protocol.HelloAck{HeartbeatSeconds: 600}) {
		t.Fatal("no change expected")
	}
}

func TestValidateServerURL(t *testing.T) {
	good := map[string]string{
		"https://rmm.example.com":       "https://rmm.example.com",
		"https://rmm.example.com:8443/": "https://rmm.example.com:8443",
		" https://127.0.0.1:8443 ":      "https://127.0.0.1:8443",
	}
	for in, want := range good {
		if got, err := ValidateServerURL(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "http://rmm.example.com", "rmm.example.com", "https://", "https://user:pw@host",
		"https://host/path", "https://host?x=1", "https://host#f", "wss://host", "file:///etc/passwd"} {
		if _, err := ValidateServerURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBootstrapTokenIsErased(t *testing.T) {
	p := testPaths(t)
	const token = "dz_enroll_SECRETSECRETSECRET"
	if err := SaveBootstrap(p, &Bootstrap{ServerURL: "https://rmm.example.com", Token: token}); err != nil {
		t.Fatal(err)
	}
	if err := EraseToken(p); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p.BootstrapFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) || strings.Contains(string(raw), "dz_enroll_") {
		t.Fatalf("token still on disk: %s", raw)
	}
	b, err := LoadBootstrap(p)
	if err != nil || b.Token != "" || b.ServerURL != "https://rmm.example.com" {
		t.Fatalf("%+v %v", b, err)
	}
	// No leftover temp file may still contain the token.
	entries, _ := os.ReadDir(p.ConfigDir)
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(p.ConfigDir, e.Name()))
		if strings.Contains(string(data), token) {
			t.Fatalf("token found in %s", e.Name())
		}
	}
	// Erasing again (or with no file) is fine.
	if err := EraseToken(p); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsBadContent(t *testing.T) {
	p := testPaths(t)
	if err := Save(p, &Config{ServerURL: "http://insecure", DeviceID: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("http server URL accepted")
	}
	if err := Save(p, &Config{ServerURL: "https://ok", DeviceID: "not-a-uuid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("bad device id accepted")
	}
}
