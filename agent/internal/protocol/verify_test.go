package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testDevice = "11111111-2222-4333-8444-555555555555"

type keyMap map[string]ed25519.PublicKey

func (k keyMap) CommandKey(kid string) (ed25519.PublicKey, bool) {
	v, ok := k[kid]
	return v, ok
}

type fixture struct {
	t      *testing.T
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	now    time.Time
	dir    string
	nonces *NonceStore
	seq    *SeqTracker
	v      *Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, pub: pub, priv: priv, now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC), dir: t.TempDir()}
	f.open()
	return f
}

// open (re)creates the verifier on top of the persisted nonce store, as after a restart.
func (f *fixture) open() {
	f.t.Helper()
	ns, err := OpenNonceStore(filepath.Join(f.dir, "nonces.json"), func() time.Time { return f.now }, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.nonces = ns
	f.seq = NewSeqTracker()
	f.v = &Verifier{DeviceID: testDevice, Keys: keyMap{"k1": f.pub}, Nonces: ns, Seq: f.seq, Now: func() time.Time { return f.now }}
}

func nonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

func (f *fixture) payload(mut func(m map[string]any)) []byte {
	m := map[string]any{
		"deviceId":  testDevice,
		"nonce":     nonce(),
		"issuedAt":  f.now.Format(time.RFC3339),
		"expiresAt": f.now.Add(5 * time.Minute).Format(time.RFC3339),
		"jobRunId":  "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"kind":      "script",
	}
	if mut != nil {
		mut(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func sign(priv ed25519.PrivateKey, kid, typ string, payload []byte) *Envelope {
	sp := base64.StdEncoding.EncodeToString(payload)
	sg := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SigningInput(typ, payload)))
	return &Envelope{Type: typ, ID: NewID(), Version: 1, SignedPayload: &sp, Signature: &sg, KeyID: &kid}
}

func (f *fixture) expect(env *Envelope, want string) *Verified {
	f.t.Helper()
	cmd, err := f.v.Verify(env)
	if want == "" {
		if err != nil {
			f.t.Fatalf("expected success, got %v", err)
		}
		return cmd
	}
	if err == nil {
		f.t.Fatalf("expected %s, got success", want)
	}
	if got := CodeOf(err); got != want {
		f.t.Fatalf("expected code %s, got %s (%v)", want, got, err)
	}
	if cmd != nil {
		f.t.Fatalf("a refused command must not be returned")
	}
	return nil
}

func TestVerifyValid(t *testing.T) {
	f := newFixture(t)
	p := f.payload(nil)
	cmd := f.expect(sign(f.priv, "k1", TypeJobDispatch, p), "")
	if string(cmd.Payload) != string(p) || cmd.DeviceID != testDevice || cmd.KeyID != "k1" {
		t.Fatalf("unexpected verified command: %+v", cmd)
	}
	var d JobDispatch
	if err := cmd.Decode(&d); err != nil || d.Kind != "script" {
		t.Fatalf("decode: %v %+v", err, d)
	}
}

func TestVerifyUnsigned(t *testing.T) {
	f := newFixture(t)
	// Plain payload only.
	f.expect(&Envelope{Type: TypeJobDispatch, ID: NewID(), Version: 1, Payload: f.payload(nil)}, ErrCodeUnsigned)
	// Missing signature.
	env := sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	env.Signature = nil
	f.expect(env, ErrCodeUnsigned)
	// Missing key id.
	env = sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	env.KeyID = nil
	f.expect(env, ErrCodeUnsigned)
	// Signed fields plus a plain payload.
	env = sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	env.Payload = json.RawMessage(`{"kind":"script"}`)
	f.expect(env, ErrCodeUnsigned)
	// Every signed type is refused when unsigned.
	for _, typ := range []string{TypeJobDispatch, TypeJobCancel, TypeUpdateAvailable, TypeSessionStart, TypeSessionInput, TypeSessionEnd, TypeTrustRotate} {
		f.expect(&Envelope{Type: typ, ID: NewID(), Version: 1, Payload: json.RawMessage(`{}`)}, ErrCodeUnsigned)
	}
	// A type that is not a signed type is never accepted by the verifier.
	f.expect(sign(f.priv, "k1", "hello.ack", f.payload(nil)), ErrCodeUnsigned)
}

func TestVerifyUnknownKey(t *testing.T) {
	f := newFixture(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	f.expect(sign(otherPriv, "attacker", TypeJobDispatch, f.payload(nil)), ErrCodeUnknownKey)
}

func TestVerifyBadSignature(t *testing.T) {
	f := newFixture(t)
	// Right kid, wrong key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	f.expect(sign(otherPriv, "k1", TypeJobDispatch, f.payload(nil)), ErrCodeBadSignature)
	// Signature for a different type (type is part of the signature input).
	env := sign(f.priv, "k1", TypeJobCancel, f.payload(nil))
	env.Type = TypeJobDispatch
	f.expect(env, ErrCodeBadSignature)
	// Truncated signature.
	env = sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	env.Signature = &short
	f.expect(env, ErrCodeBadSignature)
	// Not base64 at all.
	env = sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	junk := "!!!not base64!!!"
	env.Signature = &junk
	f.expect(env, ErrCodeMalformed)
}

func TestVerifyTamperedPayload(t *testing.T) {
	f := newFixture(t)
	env := sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	tampered := base64.StdEncoding.EncodeToString(f.payload(func(m map[string]any) { m["kind"] = "agent.uninstall" }))
	env.SignedPayload = &tampered
	_, err := f.v.Verify(env)
	if CodeOf(err) != ErrCodeBadSignature {
		t.Fatalf("expected bad_signature, got %v", err)
	}
	ve := err.(*VerifyError) //nolint:errorlint // test
	if ve.SignatureVerified || ve.Payload != nil {
		t.Fatalf("an unauthenticated payload must not be exposed")
	}
}

func TestVerifyWrongDevice(t *testing.T) {
	f := newFixture(t)
	env := sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { m["deviceId"] = "99999999-2222-4333-8444-555555555555" }))
	_, err := f.v.Verify(env)
	if CodeOf(err) != ErrCodeWrongDevice {
		t.Fatalf("expected wrong_device, got %v", err)
	}
	ve := err.(*VerifyError) //nolint:errorlint // test
	if !ve.SignatureVerified || len(ve.Payload) == 0 {
		t.Fatalf("payload of a verified signature should be available for the negative ack")
	}
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { delete(m, "deviceId") })), ErrCodeMalformed)
	f.expect(sign(f.priv, "k1", TypeJobDispatch, []byte(`[1,2,3]`)), ErrCodeMalformed)
	f.expect(sign(f.priv, "k1", TypeJobDispatch, []byte(`not json`)), ErrCodeMalformed)
}

func TestVerifyValidityWindow(t *testing.T) {
	f := newFixture(t)
	ts := func(d time.Duration) string { return f.now.Add(d).Format(time.RFC3339) }
	cases := []struct {
		name            string
		issued, expires time.Duration
		want            string
	}{
		{"expired", -10 * time.Minute, -1 * time.Second, ErrCodeExpired},
		{"expires exactly now", -1 * time.Minute, 0, ""},
		{"not yet valid", 5*time.Minute + time.Second, 9 * time.Minute, ErrCodeNotYetValid},
		{"within clock skew", 5 * time.Minute, 9 * time.Minute, ""},
		{"validity too long", 0, 15*time.Minute + time.Second, ErrCodeValidityTooLong},
		{"validity exactly 15 min", 0, 15 * time.Minute, ""},
		{"expires before issued", 2 * time.Minute, 1 * time.Minute, ErrCodeMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.t = t
			env := sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) {
				m["issuedAt"], m["expiresAt"] = ts(c.issued), ts(c.expires)
			}))
			f.expect(env, c.want)
		})
	}
	f.t = t
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { delete(m, "expiresAt") })), ErrCodeMalformed)
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { m["issuedAt"] = "yesterday" })), ErrCodeMalformed)
}

func TestVerifyReplay(t *testing.T) {
	f := newFixture(t)
	env := sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	f.expect(env, "")
	f.expect(env, ErrCodeReplayed)

	// Same nonce in a different (freshly signed) command is also a replay.
	n := nonce()
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { m["nonce"] = n })), "")
	f.expect(sign(f.priv, "k1", TypeJobCancel, f.payload(func(m map[string]any) { m["nonce"] = n })), ErrCodeReplayed)

	// Missing or malformed nonce.
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { delete(m, "nonce") })), ErrCodeMalformed)
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { m["nonce"] = "c2hvcnQ=" })), ErrCodeMalformed)
}

func TestVerifyReplayAfterRestart(t *testing.T) {
	f := newFixture(t)
	env := sign(f.priv, "k1", TypeJobDispatch, f.payload(nil))
	f.expect(env, "")

	// "Restart": a new verifier over the persisted nonces.json.
	f.open()
	f.expect(env, ErrCodeReplayed)
	// A fresh command still works after the restart.
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(nil)), "")

	// Once the command has expired the nonce may be pruned, but then the
	// command is refused as expired anyway.
	f.now = f.now.Add(11 * time.Minute)
	f.open()
	f.expect(env, ErrCodeExpired)
}

func TestVerifyFailedChecksDoNotConsumeNonce(t *testing.T) {
	f := newFixture(t)
	n := nonce()
	// Wrong device with nonce n: refused, and n must stay unused.
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) {
		m["nonce"] = n
		m["deviceId"] = "99999999-2222-4333-8444-555555555555"
	})), ErrCodeWrongDevice)
	f.expect(sign(f.priv, "k1", TypeJobDispatch, f.payload(func(m map[string]any) { m["nonce"] = n })), "")
}

func (f *fixture) input(session string, seq uint64) *Envelope {
	raw, _ := json.Marshal(map[string]any{
		"deviceId": testDevice, "sessionId": session, "seq": seq, "kind": "data", "data": "bHM=",
		"issuedAt": f.now.Format(time.RFC3339), "expiresAt": f.now.Add(time.Minute).Format(time.RFC3339),
	})
	return sign(f.priv, "k1", TypeSessionInput, raw)
}

func TestVerifySessionInputSeq(t *testing.T) {
	f := newFixture(t)
	const s1 = "aaaaaaaa-0000-4000-8000-000000000001"
	const s2 = "aaaaaaaa-0000-4000-8000-000000000002"

	// No active session: refused (and not as a replay).
	f.expect(f.input(s1, 1), ErrCodeMalformed)

	if err := f.seq.Open(s1); err != nil {
		t.Fatal(err)
	}
	// First must be 1.
	f.expect(f.input(s1, 0), ErrCodeReplayed)
	f.expect(f.input(s1, 2), ErrCodeReplayed)
	first := f.input(s1, 1)
	f.expect(first, "")
	// Replay of the same envelope and of the same seq.
	f.expect(first, ErrCodeReplayed)
	f.expect(f.input(s1, 1), ErrCodeReplayed)
	// Gap is refused, and a refused seq does not advance the counter.
	f.expect(f.input(s1, 3), ErrCodeReplayed)
	f.expect(f.input(s1, 2), "")
	f.expect(f.input(s1, 3), "")

	// Sessions are independent.
	if err := f.seq.Open(s2); err != nil {
		t.Fatal(err)
	}
	f.expect(f.input(s2, 1), "")
	f.expect(f.input(s1, 4), "")

	// After the session ended its input is refused, and the id cannot be reused.
	f.seq.Close(s1)
	f.expect(f.input(s1, 5), ErrCodeMalformed)
	if err := f.seq.Open(s1); err == nil {
		t.Fatal("a session id must not be reusable")
	}
	// Connection loss ends everything.
	f.seq.CloseAll()
	f.expect(f.input(s2, 2), ErrCodeMalformed)

	// session.input still needs a valid signature, device and validity.
	_ = f.seq.Open("aaaaaaaa-0000-4000-8000-000000000003")
	raw, _ := json.Marshal(map[string]any{
		"deviceId": testDevice, "sessionId": "aaaaaaaa-0000-4000-8000-000000000003", "seq": 1, "kind": "data",
		"issuedAt": f.now.Add(-10 * time.Minute).Format(time.RFC3339), "expiresAt": f.now.Add(-time.Minute).Format(time.RFC3339),
	})
	f.expect(sign(f.priv, "k1", TypeSessionInput, raw), ErrCodeExpired)
	// The expired input did not consume seq 1.
	f.expect(f.input("aaaaaaaa-0000-4000-8000-000000000003", 1), "")
}

// TestInteropVectors checks signed-envelope vectors produced by the server's
// C# signer (testdata/vectors.json). It is skipped until the file exists.
func TestInteropVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if os.IsNotExist(err) {
		t.Skip("testdata/vectors.json not present (generated by the server team)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		PublicKey string `json:"publicKey"`
		Kid       string `json:"kid"`
		DeviceID  string `json:"deviceId"`
		Now       string `json:"now"`
		Cases     []struct {
			Name     string          `json:"name"`
			Envelope json.RawMessage `json:"envelope"`
			Expect   string          `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vec); err != nil {
		t.Fatalf("vectors.json: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(vec.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("vectors.json: bad publicKey")
	}
	now, err := time.Parse(time.RFC3339, vec.Now)
	if err != nil {
		t.Fatalf("vectors.json: bad now: %v", err)
	}
	if len(vec.Cases) == 0 {
		t.Fatal("vectors.json has no cases")
	}
	// One store for the whole file, in order, so a vector may replay an earlier one.
	ns, err := OpenNonceStore(filepath.Join(t.TempDir(), "nonces.json"), func() time.Time { return now }, 0)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{DeviceID: vec.DeviceID, Keys: keyMap{vec.Kid: ed25519.PublicKey(pub)}, Nonces: ns, Seq: NewSeqTracker(), Now: func() time.Time { return now }}
	for _, c := range vec.Cases {
		t.Run(c.Name, func(t *testing.T) {
			env, err := ParseEnvelope(c.Envelope)
			if err != nil {
				if c.Expect == ErrCodeMalformed {
					return
				}
				t.Fatalf("envelope does not parse: %v", err)
			}
			_, verr := v.Verify(env)
			got := "ok"
			if verr != nil {
				got = CodeOf(verr)
			}
			if got != c.Expect {
				t.Fatalf("expected %q, got %q (%v)", c.Expect, got, verr)
			}
		})
	}
}

func TestEnvelopeHelpers(t *testing.T) {
	id := NewID()
	if !ValidUUID(id) {
		t.Fatalf("NewID produced %q", id)
	}
	if ValidUUID("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE") || ValidUUID("not-a-uuid") {
		t.Fatal("uppercase / garbage must not validate as an id")
	}
	data, err := NewEnvelope(TypeHeartbeat, Heartbeat{Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseEnvelope(data)
	if err != nil || env.Type != TypeHeartbeat || env.Version != 1 || !env.HasPlainPayload() {
		t.Fatalf("round trip failed: %v %+v", err, env)
	}
	if _, err := ParseEnvelope(make([]byte, MaxMessageBytes+1)); err == nil {
		t.Fatal("oversized message must be refused")
	}
	if _, err := NewEnvelope(TypeJobOutput, JobOutput{Data: string(make([]byte, MaxMessageBytes))}); err == nil {
		t.Fatal("oversized outgoing message must be refused")
	}
	for _, ok := range []string{"7zip.7zip", "git", "Mozilla.Firefox", "pkg@1.2", "a/b:c+d_e-f"} {
		if !ValidPackageID(ok) {
			t.Errorf("%q should be a valid package id", ok)
		}
	}
	for _, bad := range []string{"", "-rf", "a b", "a;b", "$(x)", "a|b", "..\\x"} {
		if ValidPackageID(bad) {
			t.Errorf("%q must not be a valid package id", bad)
		}
	}
	if !ValidEnvName("MY_VAR1") || ValidEnvName("1VAR") || ValidEnvName("A=B") || ValidEnvName("") {
		t.Error("env name validation is wrong")
	}
}
