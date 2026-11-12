// Package buildinfo carries values stamped into the binary at build time with
// -ldflags "-X ...": the agent version and the default trust anchors.
package buildinfo

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Version is the agent version (set with -ldflags -X).
var Version = "0.0.0-dev"

// EmbeddedCommandKeys is the default set of trusted Ed25519 command keys in
// the form "kid:base64pub,kid2:base64pub" (set with -ldflags -X).
var EmbeddedCommandKeys = ""

// EmbeddedCAPEMBase64 is the standard-base64 encoding of the PEM bundle of
// the pinned DranzoRMM CA certificate(s) (set with -ldflags -X).
var EmbeddedCAPEMBase64 = ""

// ParseCommandKeys parses the "kid:base64pub,kid2:base64pub" form. An empty
// string yields no keys. Key material is validated by the trust store.
func ParseCommandKeys(s string) ([]protocol.CommandKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var keys []protocol.CommandKey
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// The kid may itself contain ':'; the key is everything after the last one.
		i := strings.LastIndex(part, ":")
		if i <= 0 || i == len(part)-1 {
			return nil, fmt.Errorf("embedded command key %q is not kid:base64", part)
		}
		keys = append(keys, protocol.CommandKey{Kid: part[:i], Alg: "ed25519", PublicKey: part[i+1:]})
	}
	return keys, nil
}

// CommandKeys returns the command keys compiled into this binary.
func CommandKeys() ([]protocol.CommandKey, error) { return ParseCommandKeys(EmbeddedCommandKeys) }

// CAPEM returns the CA bundle compiled into this binary (nil if none).
func CAPEM() ([]byte, error) {
	if strings.TrimSpace(EmbeddedCAPEMBase64) == "" {
		return nil, nil
	}
	pem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(EmbeddedCAPEMBase64))
	if err != nil {
		return nil, errors.New("embedded CA bundle is not valid base64")
	}
	return pem, nil
}
