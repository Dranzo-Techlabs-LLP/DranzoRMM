package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Verification parameters (PROTOCOL.md section 4.1).
const (
	SignaturePrefix = "DRANZO-CMD-V1\n"
	ClockSkew       = 5 * time.Minute
	MaxValidity     = 15 * time.Minute
	nonceBytes      = 16
)

// KeyProvider resolves a command key id to a trusted Ed25519 public key.
// It is backed by the trust store (trust.json).
type KeyProvider interface {
	CommandKey(kid string) (ed25519.PublicKey, bool)
}

// SeqChecker is the session.input replay check (implemented by SeqTracker).
type SeqChecker interface {
	Accept(sessionID string, seq uint64) error
}

// NonceChecker is the nonce replay check (implemented by NonceStore).
type NonceChecker interface {
	CheckAndAdd(nonce string, issuedAt, keepUntil time.Time) error
}

// VerifyError is the refusal of a signed command. Code is one of the
// documented error codes. SignatureVerified tells whether the signature was
// valid; only then may Payload be inspected (e.g. to read a jobRunId for the
// negative job.ack).
type VerifyError struct {
	Code              string
	Message           string
	SignatureVerified bool
	Payload           []byte
}

func (e *VerifyError) Error() string { return e.Code + ": " + e.Message }

// CodeOf returns the protocol error code of err ("" if err is not a VerifyError).
func CodeOf(err error) string {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

// Verified is a command that passed every verification step.
type Verified struct {
	Type       string
	EnvelopeID string
	KeyID      string
	// Payload is the exact signed JSON payload bytes.
	Payload   []byte
	DeviceID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Decode unmarshals the verified payload into v.
func (c *Verified) Decode(v any) error {
	return json.Unmarshal(c.Payload, v)
}

// Verifier performs the signed-envelope verification of section 4.1 in the
// documented order. All fields are required except Now (defaults to time.Now).
type Verifier struct {
	DeviceID string
	Keys     KeyProvider
	Nonces   NonceChecker
	Seq      SeqChecker
	Now      func() time.Time
}

// SigningInput returns the exact bytes covered by the Ed25519 signature.
func SigningInput(msgType string, payload []byte) []byte {
	out := make([]byte, 0, len(SignaturePrefix)+len(msgType)+1+len(payload))
	out = append(out, SignaturePrefix...)
	out = append(out, msgType...)
	out = append(out, '\n')
	out = append(out, payload...)
	return out
}

type commonFields struct {
	DeviceID  *string    `json:"deviceId"`
	Nonce     *string    `json:"nonce"`
	IssuedAt  *time.Time `json:"issuedAt"`
	ExpiresAt *time.Time `json:"expiresAt"`
	SessionID *string    `json:"sessionId"`
	Seq       *uint64    `json:"seq"`
}

func refuse(code, format string, args ...any) *VerifyError {
	return &VerifyError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Verify checks env. On success the returned command may be executed; on any
// failure the error is a *VerifyError and nothing may be executed.
func (v *Verifier) Verify(env *Envelope) (*Verified, error) {
	// Step 1: a signed type, carried in the signed shape only.
	if env == nil || !IsSignedType(env.Type) {
		return nil, refuse(ErrCodeUnsigned, "type is not a signed command type")
	}
	if env.SignedPayload == nil || env.Signature == nil || env.KeyID == nil ||
		*env.SignedPayload == "" || *env.Signature == "" || *env.KeyID == "" {
		return nil, refuse(ErrCodeUnsigned, "%s must be signed", env.Type)
	}
	if env.HasPlainPayload() {
		return nil, refuse(ErrCodeUnsigned, "%s must not carry a plain payload", env.Type)
	}

	// Step 2: known key, valid signature over the signature input.
	if v.Keys == nil {
		return nil, refuse(ErrCodeUnknownKey, "no trusted command keys")
	}
	pub, ok := v.Keys.CommandKey(*env.KeyID)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, refuse(ErrCodeUnknownKey, "signing key is not trusted")
	}
	payload, err := base64.StdEncoding.DecodeString(*env.SignedPayload)
	if err != nil {
		return nil, refuse(ErrCodeMalformed, "signedPayload is not valid base64")
	}
	sig, err := base64.StdEncoding.DecodeString(*env.Signature)
	if err != nil {
		return nil, refuse(ErrCodeMalformed, "signature is not valid base64")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, SigningInput(env.Type, payload), sig) {
		return nil, refuse(ErrCodeBadSignature, "signature verification failed")
	}

	// From here on the payload is authentic; refusals may expose it to the caller.
	fail := func(code, format string, args ...any) (*Verified, error) {
		ve := refuse(code, format, args...)
		ve.SignatureVerified = true
		ve.Payload = payload
		return nil, ve
	}

	// Step 3: JSON object addressed to this device.
	var cf commonFields
	if err := json.Unmarshal(payload, &cf); err != nil {
		return fail(ErrCodeMalformed, "payload is not a JSON object")
	}
	if cf.DeviceID == nil || *cf.DeviceID == "" {
		return fail(ErrCodeMalformed, "payload has no deviceId")
	}
	if v.DeviceID == "" || *cf.DeviceID != v.DeviceID {
		return fail(ErrCodeWrongDevice, "command is addressed to another device")
	}

	// Step 4: validity window.
	if cf.IssuedAt == nil || cf.ExpiresAt == nil || cf.IssuedAt.IsZero() || cf.ExpiresAt.IsZero() {
		return fail(ErrCodeMalformed, "payload has no issuedAt/expiresAt")
	}
	issuedAt, expiresAt := *cf.IssuedAt, *cf.ExpiresAt
	if expiresAt.Before(issuedAt) {
		return fail(ErrCodeMalformed, "expiresAt is before issuedAt")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if now.Before(issuedAt.Add(-ClockSkew)) {
		return fail(ErrCodeNotYetValid, "command is not yet valid")
	}
	if now.After(expiresAt) {
		return fail(ErrCodeExpired, "command has expired")
	}
	if expiresAt.Sub(issuedAt) > MaxValidity {
		return fail(ErrCodeValidityTooLong, "validity period exceeds 15 minutes")
	}

	// Step 5: replay protection.
	if env.Type == TypeSessionInput {
		if cf.SessionID == nil || !ValidUUID(*cf.SessionID) || cf.Seq == nil {
			return fail(ErrCodeMalformed, "session.input needs sessionId and seq")
		}
		if v.Seq == nil {
			return fail(ErrCodeMalformed, "session not active")
		}
		switch err := v.Seq.Accept(*cf.SessionID, *cf.Seq); {
		case err == nil:
		case errors.Is(err, ErrBadSeq):
			return fail(ErrCodeReplayed, "session.input seq is not last+1")
		default:
			return fail(ErrCodeMalformed, "session not active")
		}
	} else {
		if cf.Nonce == nil {
			return fail(ErrCodeMalformed, "payload has no nonce")
		}
		raw, err := base64.StdEncoding.DecodeString(*cf.Nonce)
		if err != nil || len(raw) != nonceBytes {
			return fail(ErrCodeMalformed, "nonce must be base64 of 16 bytes")
		}
		if v.Nonces == nil {
			return fail(ErrCodeReplayed, "replay protection unavailable")
		}
		// Key by the canonical encoding so alternative base64 spellings of
		// the same bytes cannot bypass the check.
		key := base64.StdEncoding.EncodeToString(raw)
		switch err := v.Nonces.CheckAndAdd(key, issuedAt, expiresAt.Add(NonceRetention)); {
		case err == nil:
		case errors.Is(err, ErrNonceReplayed):
			return fail(ErrCodeReplayed, "nonce was already used")
		default:
			// Store full or not writable: fail closed.
			return fail(ErrCodeReplayed, "replay protection unavailable: %v", err)
		}
	}

	return &Verified{
		Type:       env.Type,
		EnvelopeID: env.ID,
		KeyID:      *env.KeyID,
		Payload:    payload,
		DeviceID:   *cf.DeviceID,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
	}, nil
}
