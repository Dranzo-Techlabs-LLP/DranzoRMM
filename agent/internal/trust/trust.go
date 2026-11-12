// Package trust implements the agent trust store (PROTOCOL.md section 1.1):
// ca.pem (the pinned DranzoRMM CA certificates that verify the server) and
// trust.json (the Ed25519 public keys allowed to sign commands).
//
// The store is written only by the installer (or from the defaults compiled
// into the binary when the files do not exist yet) and by Replace, which the
// agent calls solely for a trust.rotate command that passed signed-envelope
// verification. No unsigned input ever reaches Replace.
package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Limits on the trust store contents.
const (
	MaxCommandKeys = 16
	MaxCACerts     = 8
	maxTrustBytes  = 256 << 10
)

// ErrNotInitialised is returned by Load when the trust files do not exist and
// no defaults are available.
var ErrNotInitialised = errors.New("trust store is not initialised (ca.pem / trust.json missing)")

// File is the JSON shape of trust.json.
type File struct {
	CommandKeys []protocol.CommandKey `json:"commandKeys"`
}

// Store is the loaded trust store. It is safe for concurrent use.
type Store struct {
	caPath    string
	trustPath string

	mu    sync.RWMutex
	keys  map[string]ed25519.PublicKey
	caPEM []byte
	pool  *x509.CertPool
}

// ParseCommandKeys validates a key list and returns it as a kid -> key map.
func ParseCommandKeys(keys []protocol.CommandKey) (map[string]ed25519.PublicKey, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one command key is required")
	}
	if len(keys) > MaxCommandKeys {
		return nil, fmt.Errorf("too many command keys (max %d)", MaxCommandKeys)
	}
	out := make(map[string]ed25519.PublicKey, len(keys))
	for _, k := range keys {
		if !protocol.ValidKeyID(k.Kid) {
			return nil, fmt.Errorf("invalid key id %q", k.Kid)
		}
		if k.Alg != "ed25519" {
			return nil, fmt.Errorf("key %q: unsupported algorithm %q", k.Kid, k.Alg)
		}
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: public key must be base64 of %d bytes", k.Kid, ed25519.PublicKeySize)
		}
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("duplicate key id %q", k.Kid)
		}
		out[k.Kid] = ed25519.PublicKey(raw)
	}
	return out, nil
}

// ParseCABundle validates a PEM bundle of CA certificates and returns a pool
// containing exactly those certificates plus the normalised PEM.
func ParseCABundle(pemData []byte) (*x509.CertPool, []byte, error) {
	if len(pemData) > maxTrustBytes {
		return nil, nil, errors.New("CA bundle too large")
	}
	pool := x509.NewCertPool()
	var out bytes.Buffer
	count := 0
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("CA bundle contains a %q block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("CA bundle: %w", err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, nil, fmt.Errorf("CA bundle: %q is not a CA certificate", cert.Subject.String())
		}
		count++
		if count > MaxCACerts {
			return nil, nil, fmt.Errorf("CA bundle has too many certificates (max %d)", MaxCACerts)
		}
		pool.AddCert(cert)
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return nil, nil, err
		}
	}
	if count == 0 {
		return nil, nil, errors.New("CA bundle contains no certificates")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("CA bundle has trailing non-PEM data")
	}
	return pool, out.Bytes(), nil
}

// Install validates and writes the trust anchors. It is used by the installer
// ("dranzo-agent install --ca-file --trust-file") and when seeding the store
// from the defaults compiled into the binary.
func Install(caPath, trustPath string, caPEM []byte, keys []protocol.CommandKey) error {
	if _, err := ParseCommandKeys(keys); err != nil {
		return fmt.Errorf("trust.json: %w", err)
	}
	_, normalised, err := ParseCABundle(caPEM)
	if err != nil {
		return fmt.Errorf("ca.pem: %w", err)
	}
	data, err := json.MarshalIndent(File{CommandKeys: keys}, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(caPath, normalised); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(trustPath, append(data, '\n'))
}

// ParseFile parses the content of a trust.json file.
func ParseFile(data []byte) ([]protocol.CommandKey, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse trust.json: %w", err)
	}
	if _, err := ParseCommandKeys(f.CommandKeys); err != nil {
		return nil, err
	}
	return f.CommandKeys, nil
}

// Load reads and validates ca.pem and trust.json. Both files must be
// protected (owner-only) or the load is refused.
func Load(caPath, trustPath string) (*Store, error) {
	if !fsutil.Exists(caPath) || !fsutil.Exists(trustPath) {
		return nil, ErrNotInitialised
	}
	caPEM, err := fsutil.ReadPrivateFile(caPath, maxTrustBytes)
	if err != nil {
		return nil, fmt.Errorf("read ca.pem: %w", err)
	}
	trustData, err := fsutil.ReadPrivateFile(trustPath, maxTrustBytes)
	if err != nil {
		return nil, fmt.Errorf("read trust.json: %w", err)
	}
	pool, normalised, err := ParseCABundle(caPEM)
	if err != nil {
		return nil, fmt.Errorf("ca.pem: %w", err)
	}
	keyList, err := ParseFile(trustData)
	if err != nil {
		return nil, fmt.Errorf("trust.json: %w", err)
	}
	keys, err := ParseCommandKeys(keyList)
	if err != nil {
		return nil, fmt.Errorf("trust.json: %w", err)
	}
	return &Store{caPath: caPath, trustPath: trustPath, keys: keys, caPEM: normalised, pool: pool}, nil
}

// LoadOrSeed loads the store; when the files do not exist yet it first writes
// them from the given defaults (the anchors compiled into the binary).
func LoadOrSeed(caPath, trustPath string, defaultCAPEM []byte, defaultKeys []protocol.CommandKey) (*Store, error) {
	s, err := Load(caPath, trustPath)
	if !errors.Is(err, ErrNotInitialised) {
		return s, err
	}
	// Never mix: seed only when BOTH files are absent, otherwise a partially
	// deleted store would silently fall back to compiled-in defaults.
	if fsutil.Exists(caPath) || fsutil.Exists(trustPath) {
		return nil, fmt.Errorf("%w: one of the two files exists without the other", ErrNotInitialised)
	}
	if len(defaultCAPEM) == 0 || len(defaultKeys) == 0 {
		return nil, ErrNotInitialised
	}
	if err := Install(caPath, trustPath, defaultCAPEM, defaultKeys); err != nil {
		return nil, err
	}
	return Load(caPath, trustPath)
}

// CommandKey implements protocol.KeyProvider.
func (s *Store) CommandKey(kid string) (ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	return k, ok
}

// KeyIDs returns the sorted ids of the trusted command keys.
func (s *Store) KeyIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// CAPool returns the pool holding only the pinned CA certificates.
func (s *Store) CAPool() *x509.CertPool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pool
}

// Replace atomically replaces the command keys and, when caPEM is non-empty,
// the CA bundle. Everything is validated before anything is written.
//
// SECURITY: the only caller is the trust.rotate handler, after the command
// passed signed-envelope verification against the CURRENT trust store.
func (s *Store) Replace(keys []protocol.CommandKey, caPEM []byte) error {
	parsed, err := ParseCommandKeys(keys)
	if err != nil {
		return err
	}
	var (
		pool       *x509.CertPool
		normalised []byte
	)
	if len(caPEM) > 0 {
		pool, normalised, err = ParseCABundle(caPEM)
		if err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(File{CommandKeys: keys}, "", "  ")
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if pool != nil {
		if err := fsutil.WriteFileAtomic(s.caPath, normalised); err != nil {
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(s.trustPath, append(data, '\n')); err != nil {
		if pool != nil {
			// Roll the CA file back so the two files stay consistent.
			_ = fsutil.WriteFileAtomic(s.caPath, s.caPEM)
		}
		return err
	}
	s.keys = parsed
	if pool != nil {
		s.pool = pool
		s.caPEM = normalised
	}
	return nil
}

// ReadInstallerFiles reads and validates the --ca-file / --trust-file inputs
// of the installer.
func ReadInstallerFiles(caFile, trustFile string) ([]byte, []protocol.CommandKey, error) {
	caPEM, err := fsutil.ReadFileLimited(caFile, maxTrustBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA file: %w", err)
	}
	if _, _, err := ParseCABundle(caPEM); err != nil {
		return nil, nil, fmt.Errorf("CA file: %w", err)
	}
	data, err := fsutil.ReadFileLimited(trustFile, maxTrustBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read trust file: %w", err)
	}
	keys, err := ParseFile(data)
	if err != nil {
		return nil, nil, fmt.Errorf("trust file: %w", err)
	}
	return caPEM, keys, nil
}

// Remove deletes the trust files (used by uninstall --purge).
func Remove(caPath, trustPath string) {
	_ = os.Remove(caPath)
	_ = os.Remove(trustPath)
}
