package buildinfo

import (
	"encoding/base64"
	"testing"
)

func TestParseCommandKeys(t *testing.T) {
	keys, err := ParseCommandKeys("")
	if err != nil || keys != nil {
		t.Fatalf("empty: %v %v", keys, err)
	}
	keys, err = ParseCommandKeys("prod-2026:QUJD, kv:key:1:REVG ,")
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %v", keys, err)
	}
	if keys[0].Kid != "prod-2026" || keys[0].PublicKey != "QUJD" || keys[0].Alg != "ed25519" {
		t.Fatalf("%+v", keys[0])
	}
	if keys[1].Kid != "kv:key:1" || keys[1].PublicKey != "REVG" {
		t.Fatalf("%+v", keys[1])
	}
	for _, bad := range []string{"nokey", ":abc", "kid:"} {
		if _, err := ParseCommandKeys(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEmbeddedCA(t *testing.T) {
	old := EmbeddedCAPEMBase64
	defer func() { EmbeddedCAPEMBase64 = old }()
	EmbeddedCAPEMBase64 = ""
	if pem, err := CAPEM(); err != nil || pem != nil {
		t.Fatalf("%v %v", pem, err)
	}
	EmbeddedCAPEMBase64 = base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----"))
	if pem, err := CAPEM(); err != nil || string(pem) != "-----BEGIN CERTIFICATE-----" {
		t.Fatalf("%q %v", pem, err)
	}
	EmbeddedCAPEMBase64 = "%%%"
	if _, err := CAPEM(); err == nil {
		t.Fatal("garbage accepted")
	}
}
