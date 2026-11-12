// Package protocol defines the DranzoRMM agent <-> server wire protocol (v1)
// exactly as described in docs/PROTOCOL.md: envelopes, payload structures,
// signed-command verification and replay protection.
package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Version is the protocol major version carried in every envelope.
const Version = 1

// Subprotocol is the WebSocket subprotocol name.
const Subprotocol = "dranzo.agent.v1"

// MaxMessageBytes is the maximum WebSocket message size in either direction.
const MaxMessageBytes = 2 << 20

// Agent -> server message types.
const (
	TypeHello             = "hello"
	TypeHeartbeat         = "heartbeat"
	TypeInventory         = "inventory"
	TypeSoftwareInventory = "software.inventory"
	TypePosture           = "posture"
	TypePatchState        = "patch.state"
	TypeJobAck            = "job.ack"
	TypeJobOutput         = "job.output"
	TypeJobResult         = "job.result"
	TypeSessionStatus     = "session.status"
	TypeSessionOutput     = "session.output"
	TypeUpdateStatus      = "update.status"
	TypeError             = "error"
)

// Server -> agent message types.
const (
	TypeHelloAck        = "hello.ack"
	TypeHeartbeatAck    = "heartbeat.ack"
	TypeJobDispatch     = "job.dispatch"
	TypeJobCancel       = "job.cancel"
	TypeUpdateAvailable = "update.available"
	TypeSessionStart    = "session.start"
	TypeSessionInput    = "session.input"
	TypeSessionEnd      = "session.end"
	TypeTrustRotate     = "trust.rotate"
)

// Error codes used in "error" messages.
const (
	ErrCodeUnsigned           = "unsigned"
	ErrCodeUnknownKey         = "unknown_key"
	ErrCodeBadSignature       = "bad_signature"
	ErrCodeWrongDevice        = "wrong_device"
	ErrCodeExpired            = "expired"
	ErrCodeNotYetValid        = "not_yet_valid"
	ErrCodeValidityTooLong    = "validity_too_long"
	ErrCodeReplayed           = "replayed"
	ErrCodeMalformed          = "malformed"
	ErrCodeUnsupportedVersion = "unsupported_version"
	ErrCodeUnknownType        = "unknown_type"
)

// signedTypes are the server -> agent types that must always be signed.
var signedTypes = map[string]struct{}{
	TypeJobDispatch:     {},
	TypeJobCancel:       {},
	TypeUpdateAvailable: {},
	TypeSessionStart:    {},
	TypeSessionInput:    {},
	TypeSessionEnd:      {},
	TypeTrustRotate:     {},
}

// IsSignedType reports whether t is a type that must arrive in a signed envelope.
func IsSignedType(t string) bool {
	_, ok := signedTypes[t]
	return ok
}

// Envelope is the single JSON object carried in every WebSocket text frame.
// Plain messages use Payload; signed commands use SignedPayload, Signature and
// KeyID instead (never both).
type Envelope struct {
	Type          string          `json:"type"`
	ID            string          `json:"id"`
	Version       int             `json:"version"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	SignedPayload *string         `json:"signedPayload,omitempty"`
	Signature     *string         `json:"signature,omitempty"`
	KeyID         *string         `json:"keyId,omitempty"`
}

// HasPlainPayload reports whether the envelope carries a non-null plain payload.
func (e *Envelope) HasPlainPayload() bool {
	return len(e.Payload) > 0 && string(e.Payload) != "null"
}

// ParseEnvelope decodes one message. It enforces the size limit and the
// presence of a type; everything else is validated by the caller.
func ParseEnvelope(data []byte) (*Envelope, error) {
	if len(data) > MaxMessageBytes {
		return nil, errors.New("message exceeds size limit")
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("invalid envelope JSON: %w", err)
	}
	if env.Type == "" || len(env.Type) > 64 {
		return nil, errors.New("envelope has no valid type")
	}
	if len(env.ID) > 64 {
		return nil, errors.New("envelope id too long")
	}
	return &env, nil
}

// NewEnvelope builds a plain (unsigned) agent -> server message.
func NewEnvelope(msgType string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal %s payload: %w", msgType, err)
	}
	data, err := json.Marshal(Envelope{Type: msgType, ID: NewID(), Version: Version, Payload: raw})
	if err != nil {
		return nil, fmt.Errorf("marshal %s envelope: %w", msgType, err)
	}
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("%s message of %d bytes exceeds the %d byte limit", msgType, len(data), MaxMessageBytes)
	}
	return data, nil
}

// NewID returns a random (version 4) lowercase UUID string.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never fails on supported platforms; treat as fatal.
		panic("crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

var (
	uuidRe      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	packageIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,199}$`)
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	kindRe      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	keyIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidUUID reports whether s is a lowercase UUID string as used for all IDs.
func ValidUUID(s string) bool { return uuidRe.MatchString(s) }

// ValidPackageID reports whether s is acceptable as a packageId, version or
// updateId (PROTOCOL.md section 6.2).
func ValidPackageID(s string) bool { return packageIDRe.MatchString(s) }

// ValidEnvName reports whether s is an acceptable environment variable name.
func ValidEnvName(s string) bool { return envNameRe.MatchString(s) }

// ValidKind reports whether s is a syntactically valid job kind.
func ValidKind(s string) bool { return kindRe.MatchString(s) }

// ValidKeyID reports whether s is a syntactically valid command key id.
func ValidKeyID(s string) bool { return keyIDRe.MatchString(s) }

// ValidSHA256Hex reports whether s is a lowercase hex SHA-256 digest.
func ValidSHA256Hex(s string) bool { return sha256HexRe.MatchString(s) }
