// Package identity manages the device identity: the locally generated ECDSA
// P-256 key pair, the client certificate issued by the DranzoRMM private CA,
// enrollment, renewal and the atomic switch to a renewed certificate.
//
// The private key is generated on the device, stored owner-only and never
// transmitted or logged.
package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

const (
	maxPEMBytes     = 256 << 10
	deviceURIPrefix = "urn:dranzo:device:"
	nextSuffix      = ".next"
)

// ErrNoIdentity is returned by Store.Load when the device is not enrolled.
var ErrNoIdentity = errors.New("device identity not found (not enrolled)")

// Identity is a device key pair with its certificate.
type Identity struct {
	DeviceID string
	// TLS is ready for use as a TLS client certificate (Leaf is set).
	TLS     tls.Certificate
	Leaf    *x509.Certificate
	keyPEM  []byte
	certPEM []byte
}

// Thumbprint returns the hex SHA-256 of the leaf certificate (DER).
func (id *Identity) Thumbprint() string {
	sum := sha256.Sum256(id.Leaf.Raw)
	return hex.EncodeToString(sum[:])
}

// GenerateKey creates a new ECDSA P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewCSR builds a PEM certificate signing request for key. The subject is
// informational only: the server ignores it and assigns CN=<deviceId>.
func NewCSR(key *ecdsa.PrivateKey, hostname string) ([]byte, error) {
	if len(hostname) > 64 {
		hostname = hostname[:64]
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: hostname},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// NeedsRenewal reports whether less than one third of the certificate
// lifetime remains at now (PROTOCOL.md section 2.2).
func NeedsRenewal(leaf *x509.Certificate, now time.Time) bool {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	remaining := leaf.NotAfter.Sub(now)
	return remaining < lifetime/3
}

// parseCertificates decodes every CERTIFICATE block of a PEM bundle.
func parseCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
		if len(certs) > 16 {
			return nil, errors.New("too many certificates")
		}
	}
	return certs, nil
}

// fromResponse validates a certificate returned by enroll/renew and combines
// it with the locally generated key.
//
// The certificate must: belong to our key, chain to the PINNED roots (the
// caCertificates of the response are used as untrusted intermediates only and
// never become trust anchors), allow client authentication, be currently
// valid, and name the device id as CN and as SAN URI urn:dranzo:device:<id>.
func fromResponse(key *ecdsa.PrivateKey, resp *protocol.CertificateResponse, roots *x509.CertPool, now time.Time) (*Identity, error) {
	if !protocol.ValidUUID(resp.DeviceID) {
		return nil, errors.New("server returned an invalid device id")
	}
	if len(resp.Certificate) > maxPEMBytes || len(resp.CACertificates) > maxPEMBytes {
		return nil, errors.New("server returned an oversized certificate")
	}
	leafs, err := parseCertificates([]byte(resp.Certificate))
	if err != nil || len(leafs) == 0 {
		return nil, errors.New("server returned no valid certificate")
	}
	leaf := leafs[0]
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("issued certificate does not match the device key")
	}
	if leaf.Subject.CommonName != resp.DeviceID {
		return nil, errors.New("issued certificate CN does not match the device id")
	}
	uriOK := false
	for _, u := range leaf.URIs {
		if u.String() == deviceURIPrefix+resp.DeviceID {
			uriOK = true
		}
	}
	if !uriOK {
		return nil, errors.New("issued certificate lacks the device SAN URI")
	}
	inter := x509.NewCertPool()
	for _, c := range leafs[1:] {
		inter.AddCert(c)
	}
	extra, err := parseCertificates([]byte(resp.CACertificates))
	if err != nil {
		return nil, errors.New("server returned invalid CA certificates")
	}
	for _, c := range extra {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, fmt.Errorf("issued certificate does not chain to the pinned CA: %w", err)
	}

	// device.crt = leaf followed by any intermediates (never the root).
	var certPEM bytes.Buffer
	chain := chains[0]
	for i, c := range chain {
		if i > 0 && i == len(chain)-1 {
			break
		}
		if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return nil, err
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return build(keyPEM, certPEM.Bytes())
}

// build parses a stored key/certificate pair.
func build(keyPEM, certPEM []byte) (*Identity, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("device key and certificate do not form a pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	if !protocol.ValidUUID(leaf.Subject.CommonName) {
		return nil, errors.New("device certificate CN is not a device id")
	}
	return &Identity{DeviceID: leaf.Subject.CommonName, TLS: pair, Leaf: leaf, keyPEM: keyPEM, certPEM: certPEM}, nil
}

// Store persists the identity as device.key (PKCS#8 PEM) and device.crt.
type Store struct {
	keyPath  string
	certPath string
}

// NewStore returns a store for the given files.
func NewStore(keyPath, certPath string) *Store {
	return &Store{keyPath: keyPath, certPath: certPath}
}

// Load reads the identity, first completing a switch to a renewed
// certificate that was interrupted by a crash. A missing identity yields
// ErrNoIdentity.
func (s *Store) Load() (*Identity, error) {
	s.recover()
	if !fsutil.Exists(s.keyPath) && !fsutil.Exists(s.certPath) {
		return nil, ErrNoIdentity
	}
	keyPEM, err := fsutil.ReadPrivateFile(s.keyPath, maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("read device key: %w", err)
	}
	certPEM, err := fsutil.ReadPrivateFile(s.certPath, maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("read device certificate: %w", err)
	}
	return build(keyPEM, certPEM)
}

// recover finishes (or discards) a half-done Save.
//
// Save writes key.next, then crt.next, then renames key, then crt. So:
//   - key.next only: the write was interrupted; the old pair is intact.
//   - key.next + crt.next: nothing renamed yet; complete the switch.
//   - crt.next only: the key was already renamed; complete the switch.
func (s *Store) recover() {
	keyNext, certNext := s.keyPath+nextSuffix, s.certPath+nextSuffix
	hasKey, hasCert := fsutil.Exists(keyNext), fsutil.Exists(certNext)
	switch {
	case hasKey && !hasCert:
		_ = os.Remove(keyNext)
	case hasKey && hasCert:
		if os.Rename(keyNext, s.keyPath) == nil {
			_ = os.Rename(certNext, s.certPath)
		}
	case hasCert:
		_ = os.Rename(certNext, s.certPath)
	}
}

// Save stores a new identity. The new files are fully written (and synced)
// before the old ones are replaced by rename; Load repairs an interrupted switch.
func (s *Store) Save(id *Identity) error {
	keyNext, certNext := s.keyPath+nextSuffix, s.certPath+nextSuffix
	_ = os.Remove(certNext)
	if err := fsutil.WriteFileAtomic(keyNext, id.keyPEM); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(certNext, id.certPEM); err != nil {
		_ = os.Remove(keyNext)
		return err
	}
	if err := os.Rename(keyNext, s.keyPath); err != nil {
		return fmt.Errorf("switch device key: %w", err)
	}
	if err := os.Rename(certNext, s.certPath); err != nil {
		return fmt.Errorf("switch device certificate: %w", err)
	}
	return nil
}

// Remove deletes the identity files (used by uninstall).
func (s *Store) Remove() {
	for _, p := range []string{s.keyPath, s.certPath, s.keyPath + nextSuffix, s.certPath + nextSuffix} {
		_ = os.Remove(p)
	}
}
