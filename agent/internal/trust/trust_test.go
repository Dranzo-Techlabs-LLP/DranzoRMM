package trust

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func testCA(t *testing.T, name string, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testKey(t *testing.T, kid string) protocol.CommandKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.CommandKey{Kid: kid, Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func TestStoreInstallLoadReplace(t *testing.T) {
	dir := t.TempDir()
	caPath, trustPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "trust.json")
	if _, err := Load(caPath, trustPath); !errors.Is(err, ErrNotInitialised) {
		t.Fatalf("expected ErrNotInitialised, got %v", err)
	}
	ca1, k1 := testCA(t, "CA 1", true), testKey(t, "k1")
	if err := Install(caPath, trustPath, ca1, []protocol.CommandKey{k1}); err != nil {
		t.Fatal(err)
	}
	s, err := Load(caPath, trustPath)
	if err != nil {
		t.Fatal(err)
	}
	if ids := s.KeyIDs(); len(ids) != 1 || ids[0] != "k1" {
		t.Fatalf("key ids %v", ids)
	}
	if _, ok := s.CommandKey("k1"); !ok {
		t.Fatal("k1 missing")
	}
	if _, ok := s.CommandKey("k2"); ok {
		t.Fatal("unknown key reported as trusted")
	}

	// Replace keys only: the CA stays.
	k2 := testKey(t, "k2")
	oldPool := s.CAPool()
	if err := s.Replace([]protocol.CommandKey{k2}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.CommandKey("k1"); ok {
		t.Fatal("old key still trusted after rotation")
	}
	if _, ok := s.CommandKey("k2"); !ok {
		t.Fatal("new key not trusted")
	}
	if !s.CAPool().Equal(oldPool) {
		t.Fatal("CA changed although none was supplied")
	}
	// Replace keys and CA; the change is persisted.
	ca2 := testCA(t, "CA 2", true)
	if err := s.Replace([]protocol.CommandKey{k1, k2}, ca2); err != nil {
		t.Fatal(err)
	}
	if s.CAPool().Equal(oldPool) {
		t.Fatal("CA not replaced")
	}
	reloaded, err := Load(caPath, trustPath)
	if err != nil {
		t.Fatal(err)
	}
	if ids := reloaded.KeyIDs(); len(ids) != 2 {
		t.Fatalf("persisted key ids %v", ids)
	}
	if !reloaded.CAPool().Equal(s.CAPool()) {
		t.Fatal("persisted CA differs")
	}
}

func TestReplaceValidatesBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	caPath, trustPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "trust.json")
	ca1, k1 := testCA(t, "CA 1", true), testKey(t, "k1")
	if err := Install(caPath, trustPath, ca1, []protocol.CommandKey{k1}); err != nil {
		t.Fatal(err)
	}
	s, _ := Load(caPath, trustPath)
	before, _ := os.ReadFile(trustPath)
	caBefore, _ := os.ReadFile(caPath)

	short := protocol.CommandKey{Kid: "bad", Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString([]byte("short"))}
	rsa := protocol.CommandKey{Kid: "rsa", Alg: "rsa", PublicKey: k1.PublicKey}
	badKid := protocol.CommandKey{Kid: "has space", Alg: "ed25519", PublicKey: k1.PublicKey}
	var tooMany []protocol.CommandKey
	for i := 0; i < MaxCommandKeys+1; i++ {
		tooMany = append(tooMany, testKey(t, "k"+string(rune('a'+i))))
	}
	attempts := []struct {
		name string
		keys []protocol.CommandKey
		ca   []byte
	}{
		{"no keys", nil, nil},
		{"short key", []protocol.CommandKey{short}, nil},
		{"wrong alg", []protocol.CommandKey{rsa}, nil},
		{"bad kid", []protocol.CommandKey{badKid}, nil},
		{"duplicate kid", []protocol.CommandKey{k1, k1}, nil},
		{"too many", tooMany, nil},
		{"CA is garbage", []protocol.CommandKey{k1}, []byte("not a certificate")},
		{"CA is a leaf", []protocol.CommandKey{k1}, testCA(t, "leaf", false)},
		{"CA has trailing junk", []protocol.CommandKey{k1}, append(testCA(t, "x", true), []byte("junk")...)},
	}
	for _, a := range attempts {
		if err := s.Replace(a.keys, a.ca); err == nil {
			t.Errorf("%s: accepted", a.name)
		}
	}
	after, _ := os.ReadFile(trustPath)
	caAfter, _ := os.ReadFile(caPath)
	if string(before) != string(after) || string(caBefore) != string(caAfter) {
		t.Fatal("a refused replacement modified the trust store on disk")
	}
	if ids := s.KeyIDs(); len(ids) != 1 || ids[0] != "k1" {
		t.Fatalf("a refused replacement modified the trust store in memory: %v", ids)
	}
}

func TestLoadOrSeed(t *testing.T) {
	dir := t.TempDir()
	caPath, trustPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "trust.json")
	if _, err := LoadOrSeed(caPath, trustPath, nil, nil); !errors.Is(err, ErrNotInitialised) {
		t.Fatalf("no defaults: %v", err)
	}
	ca, k := testCA(t, "embedded", true), testKey(t, "embedded-1")
	s, err := LoadOrSeed(caPath, trustPath, ca, []protocol.CommandKey{k})
	if err != nil {
		t.Fatal(err)
	}
	if ids := s.KeyIDs(); len(ids) != 1 || ids[0] != "embedded-1" {
		t.Fatalf("%v", ids)
	}
	// Existing files win over (different) compiled-in defaults.
	s2, err := LoadOrSeed(caPath, trustPath, testCA(t, "other", true), []protocol.CommandKey{testKey(t, "other-1")})
	if err != nil || s2.KeyIDs()[0] != "embedded-1" {
		t.Fatalf("existing store was overridden: %v %v", s2.KeyIDs(), err)
	}
	// A half-deleted store is an error, never a silent re-seed.
	if err := os.Remove(trustPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrSeed(caPath, trustPath, ca, []protocol.CommandKey{k}); err == nil {
		t.Fatal("half-deleted trust store was re-seeded")
	}
}
