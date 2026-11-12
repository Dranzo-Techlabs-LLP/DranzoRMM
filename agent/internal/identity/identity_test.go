package identity_test

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/identity"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

func server(t *testing.T, opts testserver.Options) (*testserver.Server, *x509.CertPool) {
	t.Helper()
	s, err := testserver.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.CAPEM)
	return s, pool
}

func enroll(t *testing.T, s *testserver.Server, pool *x509.CertPool, token string) (*identity.Identity, error) {
	t.Helper()
	client := transport.NewHTTPClient(transport.NewTLSConfig(pool, nil), 10*time.Second)
	return identity.Enroll(context.Background(), client, s.URL, identity.EnrollParams{
		Token: token, Hostname: "host", OS: "linux", Arch: "arm64", AgentVersion: "1", MachineID: "m",
	}, pool)
}

func TestNeedsRenewal(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}
	if identity.NeedsRenewal(leaf, start.Add(59*24*time.Hour)) {
		t.Fatal("renewed with more than a third of the lifetime left")
	}
	if !identity.NeedsRenewal(leaf, start.Add(60*24*time.Hour+time.Second)) {
		t.Fatal("not renewed with less than a third of the lifetime left")
	}
	if !identity.NeedsRenewal(leaf, start.Add(100*24*time.Hour)) {
		t.Fatal("expired certificate must need renewal")
	}
}

func TestEnrollStoreAndRenew(t *testing.T) {
	s, pool := server(t, testserver.Options{})
	if _, err := enroll(t, s, pool, "dz_enroll_wrong"); !errors.Is(err, identity.ErrTokenRejected) {
		t.Fatalf("wrong token: %v", err)
	}
	id, err := enroll(t, s, pool, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	if id.DeviceID == "" || id.Leaf.Subject.CommonName != id.DeviceID {
		t.Fatalf("bad identity %+v", id.Leaf.Subject)
	}
	if cur, _ := s.Thumbprints(id.DeviceID); cur != id.Thumbprint() {
		t.Fatal("thumbprint mismatch")
	}

	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "device.key"), filepath.Join(dir, "device.crt")
	store := identity.NewStore(keyPath, certPath)
	if _, err := store.Load(); !errors.Is(err, identity.ErrNoIdentity) {
		t.Fatalf("expected ErrNoIdentity, got %v", err)
	}
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := os.ReadFile(keyPath)
	if !strings.HasPrefix(string(keyPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("device.key is not PKCS#8 PEM")
	}
	if os.PathSeparator == '/' {
		if fi, _ := os.Stat(keyPath); fi.Mode().Perm() != 0o600 {
			t.Fatalf("device.key mode %v", fi.Mode().Perm())
		}
	}
	loaded, err := store.Load()
	if err != nil || loaded.DeviceID != id.DeviceID || loaded.Thumbprint() != id.Thumbprint() {
		t.Fatalf("load: %v", err)
	}

	// Renew over mTLS: same device, new key, new certificate.
	mtls := transport.NewHTTPClient(transport.NewTLSConfig(pool, func() *tlsCert { return &loaded.TLS }), 10*time.Second)
	renewed, err := identity.Renew(context.Background(), mtls, s.URL, loaded, pool)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.DeviceID != id.DeviceID || renewed.Thumbprint() == id.Thumbprint() {
		t.Fatal("renewal did not produce a new certificate for the same device")
	}
	if cur, prev := s.Thumbprints(id.DeviceID); cur != renewed.Thumbprint() || prev != id.Thumbprint() {
		t.Fatal("server state after renew is wrong")
	}
	if err := store.Save(renewed); err != nil {
		t.Fatal(err)
	}
	again, err := store.Load()
	if err != nil || again.Thumbprint() != renewed.Thumbprint() {
		t.Fatalf("switch failed: %v", err)
	}
	// Renew without a client certificate is refused.
	anon := transport.NewHTTPClient(transport.NewTLSConfig(pool, nil), 10*time.Second)
	if _, err := identity.Renew(context.Background(), anon, s.URL, loaded, pool); err == nil {
		t.Fatal("renew without client certificate succeeded")
	}
}

func TestIssuedCertificateMustChainToPinnedCA(t *testing.T) {
	// The agent talks to a server it trusts for TLS, but validates the issued
	// device certificate against the pinned roots as well: a response whose
	// certificate comes from another CA is refused.
	s, _ := server(t, testserver.Options{})
	other, otherPool := server(t, testserver.Options{})
	_ = other
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.CAPEM)
	client := transport.NewHTTPClient(transport.NewTLSConfig(pool, nil), 10*time.Second)
	_, err := identity.Enroll(context.Background(), client, s.URL, identity.EnrollParams{Token: s.Token}, otherPool)
	if err == nil || !strings.Contains(err.Error(), "pinned CA") {
		t.Fatalf("expected a pinned CA failure, got %v", err)
	}
}

func TestStoreRecoversInterruptedSwitch(t *testing.T) {
	s, pool := server(t, testserver.Options{})
	oldID, err := enroll(t, s, pool, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	newID, err := enroll(t, s, pool, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	read := func(dir, name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	// Capture the file contents of both identities.
	tmpOld, tmpNew := t.TempDir(), t.TempDir()
	_ = identity.NewStore(filepath.Join(tmpOld, "device.key"), filepath.Join(tmpOld, "device.crt")).Save(oldID)
	_ = identity.NewStore(filepath.Join(tmpNew, "device.key"), filepath.Join(tmpNew, "device.crt")).Save(newID)
	oldKey, oldCrt := read(tmpOld, "device.key"), read(tmpOld, "device.crt")
	newKey, newCrt := read(tmpNew, "device.key"), read(tmpNew, "device.crt")

	write := func(dir, name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		files map[string][]byte
		want  string
	}{
		{"crash after writing only key.next", map[string][]byte{"device.key": oldKey, "device.crt": oldCrt, "device.key.next": newKey}, oldID.Thumbprint()},
		{"crash before any rename", map[string][]byte{"device.key": oldKey, "device.crt": oldCrt, "device.key.next": newKey, "device.crt.next": newCrt}, newID.Thumbprint()},
		{"crash between the two renames", map[string][]byte{"device.key": newKey, "device.crt": oldCrt, "device.crt.next": newCrt}, newID.Thumbprint()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range c.files {
				write(dir, name, data)
			}
			got, err := identity.NewStore(filepath.Join(dir, "device.key"), filepath.Join(dir, "device.crt")).Load()
			if err != nil {
				t.Fatalf("identity unusable after crash: %v", err)
			}
			if got.Thumbprint() != c.want {
				t.Fatal("wrong identity selected after recovery")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 2 {
				t.Fatalf("leftover files: %v", entries)
			}
		})
	}
}
