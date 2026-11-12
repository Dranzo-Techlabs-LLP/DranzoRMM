// Package testserver is an in-process fake of the DranzoRMM agent gateway
// for tests and local development: a throwaway CA, an Ed25519 command key,
// /agent/v1/enroll, /agent/v1/renew, /agent/v1/ws (with client-certificate
// verification), blob download / upload and helpers for signing commands.
//
// It is NOT the real server and must never be used in production: its keys
// live in memory and it issues a certificate to anyone who knows the token.
package testserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Options configures a fake server.
type Options struct {
	// Token is the accepted enrollment token (default: a random one).
	Token string
	// CertValidity is the lifetime of issued device certificates (default 90 days).
	CertValidity time.Duration
	// BackdateFirstCert issues the enrollment certificate as if most of its
	// lifetime had already passed, so the agent renews immediately.
	BackdateFirstCert bool
	// HeartbeatSeconds is announced in hello.ack (default 60).
	HeartbeatSeconds int
	// InventoryIntervalSeconds is announced in hello.ack (default 3600).
	InventoryIntervalSeconds int
	// Listener, if set, is used instead of a random localhost port.
	Listener net.Listener
	// ExtraHosts are added to the server certificate (DNS names or IPs).
	ExtraHosts []string
}

type device struct {
	id       string
	current  string // SHA-256 thumbprint of the current certificate
	previous string
	revoked  bool
	conn     *websocket.Conn
	connCtx  context.Context
	hello    *protocol.Hello
	messages []*protocol.Envelope
	// thumbprints of the certificates used for each WebSocket connection
	connThumbprints []string
}

// Server is a running fake gateway.
type Server struct {
	// URL is the https origin of the listener.
	URL string
	// Token is the enrollment token.
	Token string
	// CAPEM is the PEM of the throwaway CA (the agent's ca.pem).
	CAPEM []byte
	// KeyID is the kid of the command signing key.
	KeyID string

	opts    Options
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	cmdPub  ed25519.PublicKey
	cmdPriv ed25519.PrivateKey
	srv     *httptest.Server

	mu       sync.Mutex
	changed  chan struct{}
	devices  map[string]*device
	enrolls  int
	renews   int
	blobs    map[string][]byte
	uploads  map[string][]byte
	serial   int64
	httpHits map[string]int
}

// New starts a fake server.
func New(opts Options) (*Server, error) {
	if opts.CertValidity <= 0 {
		opts.CertValidity = 90 * 24 * time.Hour
	}
	if opts.HeartbeatSeconds <= 0 {
		opts.HeartbeatSeconds = 60
	}
	if opts.InventoryIntervalSeconds <= 0 {
		opts.InventoryIntervalSeconds = 3600
	}
	if opts.Token == "" {
		var b [18]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		opts.Token = "dz_enroll_" + hex.EncodeToString(b[:])
	}
	s := &Server{
		Token:    opts.Token,
		KeyID:    "test-key-1",
		opts:     opts,
		changed:  make(chan struct{}),
		devices:  map[string]*device{},
		blobs:    map[string][]byte{},
		uploads:  map[string][]byte{},
		serial:   1000,
		httpHits: map[string]int{},
	}

	// Throwaway CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DranzoRMM Test CA", Organization: []string{"DranzoRMM test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	s.caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	s.caKey = caKey
	s.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Command signing key.
	s.cmdPub, s.cmdPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Server certificate for localhost.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	for _, h := range opts.ExtraHosts {
		if ip := net.ParseIP(h); ip != nil {
			srvTmpl.IPAddresses = append(srvTmpl.IPAddresses, ip)
		} else if h != "" {
			srvTmpl.DNSNames = append(srvTmpl.DNSNames, h)
		}
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, s.caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(s.caCert)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /agent/v1/renew", s.handleRenew)
	mux.HandleFunc("GET /agent/v1/ws", s.handleWS)
	mux.HandleFunc("GET /agent/v1/blobs/{id}", s.handleBlob)
	mux.HandleFunc("PUT /agent/v1/uploads/{id}", s.handleUpload)

	s.srv = httptest.NewUnstartedServer(mux)
	if opts.Listener != nil {
		_ = s.srv.Listener.Close()
		s.srv.Listener = opts.Listener
	}
	s.srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCAs,
	}
	// Failed TLS handshakes are expected in negative tests; keep them out of the output.
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.StartTLS()
	s.URL = s.srv.URL
	return s, nil
}

// Close stops the server and drops every connection.
func (s *Server) Close() {
	s.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.devices))
	for _, d := range s.devices {
		if d.conn != nil {
			conns = append(conns, d.conn)
		}
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseNow()
	}
	s.srv.CloseClientConnections()
	s.srv.Close()
}

// PublicKey returns the command signing public key.
func (s *Server) PublicKey() ed25519.PublicKey { return s.cmdPub }

// TrustKeys returns the trust.json content as protocol keys.
func (s *Server) TrustKeys() []protocol.CommandKey {
	return []protocol.CommandKey{{Kid: s.KeyID, Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(s.cmdPub)}}
}

// TrustJSON returns the trust.json file content.
func (s *Server) TrustJSON() []byte {
	data, _ := json.MarshalIndent(map[string]any{"commandKeys": s.TrustKeys()}, "", "  ")
	return data
}

// WriteInstallerFiles writes ca.pem and trust.json into dir (as inputs for
// "dranzo-agent install --ca-file --trust-file") and returns their paths.
func (s *Server) WriteInstallerFiles(dir string) (caFile, trustFile string, err error) {
	caFile = filepath.Join(dir, "ca.pem")
	trustFile = filepath.Join(dir, "trust.json")
	if err := os.WriteFile(caFile, s.CAPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(trustFile, s.TrustJSON(), 0o600); err != nil {
		return "", "", err
	}
	return caFile, trustFile, nil
}

func (s *Server) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Server) hit(name string) {
	s.mu.Lock()
	s.httpHits[name]++
	s.mu.Unlock()
}

// Hits returns how often an endpoint ("enroll", "renew", "ws", "blob",
// "upload") was reached at the HTTP level, including rejected requests.
func (s *Server) Hits(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpHits[name]
}

func thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func (s *Server) issue(csrPEM, deviceID string, backdate bool) (certPEM []byte, cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("CSR key must be ECDSA P-256")
	}
	uri, err := url.Parse("urn:dranzo:device:" + deviceID)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.Add(s.opts.CertValidity)
	if backdate {
		// 90% of the lifetime is already gone: less than one third remains.
		notBefore = time.Now().Add(-s.opts.CertValidity * 9 / 10)
		notAfter = notBefore.Add(s.opts.CertValidity)
	}
	s.mu.Lock()
	s.serial++
	serial := s.serial
	s.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	s.hit("enroll")
	var req protocol.EnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "malformed", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.Token)) != 1 {
		http.Error(w, "enrollment refused", http.StatusUnauthorized)
		return
	}
	deviceID := protocol.NewID()
	certPEM, cert, err := s.issue(req.CSR, deviceID, s.opts.BackdateFirstCert)
	if err != nil {
		http.Error(w, "malformed", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.devices[deviceID] = &device{id: deviceID, current: thumbprint(cert)}
	s.enrolls++
	s.notifyLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, protocol.CertificateResponse{
		DeviceID: deviceID, Certificate: string(certPEM), CACertificates: string(s.CAPEM), NotAfter: cert.NotAfter.UTC(),
	})
}

// authDevice maps the verified client certificate to a device, enforcing the
// thumbprint and revocation checks of PROTOCOL.md section 2.3.
func (s *Server) authDevice(r *http.Request) (dev *device, tp string, status int) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, "", http.StatusUnauthorized
	}
	cert := r.TLS.PeerCertificates[0]
	tp = thumbprint(cert)
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[cert.Subject.CommonName]
	if d == nil || d.revoked {
		return nil, tp, http.StatusForbidden
	}
	if tp != d.current && tp != d.previous {
		return nil, tp, http.StatusForbidden
	}
	return d, tp, http.StatusOK
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	s.hit("renew")
	d, _, status := s.authDevice(r)
	if d == nil {
		http.Error(w, "refused", status)
		return
	}
	var req protocol.RenewRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "malformed", http.StatusBadRequest)
		return
	}
	certPEM, cert, err := s.issue(req.CSR, d.id, false)
	if err != nil {
		http.Error(w, "malformed", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	d.previous = d.current
	d.current = thumbprint(cert)
	s.renews++
	s.notifyLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, protocol.CertificateResponse{
		DeviceID: d.id, Certificate: string(certPEM), CACertificates: string(s.CAPEM), NotAfter: cert.NotAfter.UTC(),
	})
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	s.hit("ws")
	d, tp, status := s.authDevice(r)
	if d == nil {
		http.Error(w, "refused", status)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.Subprotocol}})
	if err != nil {
		return
	}
	if conn.Subprotocol() != protocol.Subprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}
	conn.SetReadLimit(protocol.MaxMessageBytes)
	ctx := r.Context()

	// First message must be hello.
	_, data, err := conn.Read(ctx)
	if err != nil {
		return
	}
	env, err := protocol.ParseEnvelope(data)
	if err != nil || env.Type != protocol.TypeHello {
		_ = conn.Close(websocket.StatusPolicyViolation, "hello expected")
		return
	}
	var hello protocol.Hello
	if err := json.Unmarshal(env.Payload, &hello); err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "bad hello")
		return
	}

	s.mu.Lock()
	old := d.conn
	d.conn, d.connCtx = conn, ctx
	d.hello = &hello
	d.messages = append(d.messages, env)
	d.connThumbprints = append(d.connThumbprints, tp)
	if tp == d.current {
		// First successful connection with the new certificate retires the old one.
		d.previous = ""
	}
	s.notifyLocked()
	s.mu.Unlock()
	if old != nil {
		_ = old.Close(websocket.StatusPolicyViolation, "replaced by a new connection")
	}

	ack, _ := protocol.NewEnvelope(protocol.TypeHelloAck, protocol.HelloAck{
		ServerTime:               time.Now().UTC(),
		HeartbeatSeconds:         s.opts.HeartbeatSeconds,
		InventoryIntervalSeconds: s.opts.InventoryIntervalSeconds,
		SoftwareIntervalSeconds:  86400,
		PostureIntervalSeconds:   3600,
		PatchScanIntervalSeconds: 43200,
	})
	if err := conn.Write(ctx, websocket.MessageText, ack); err != nil {
		return
	}

	defer func() {
		s.mu.Lock()
		if d.conn == conn {
			d.conn = nil
		}
		s.notifyLocked()
		s.mu.Unlock()
		_ = conn.CloseNow()
	}()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		env, err := protocol.ParseEnvelope(data)
		if err != nil {
			continue
		}
		s.mu.Lock()
		d.messages = append(d.messages, env)
		s.notifyLocked()
		s.mu.Unlock()
		if env.Type == protocol.TypeHeartbeat {
			hb, _ := protocol.NewEnvelope(protocol.TypeHeartbeatAck, protocol.HeartbeatAck{ServerTime: time.Now().UTC()})
			if err := conn.Write(ctx, websocket.MessageText, hb); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request) {
	s.hit("blob")
	if d, _, status := s.authDevice(r); d == nil {
		http.Error(w, "refused", status)
		return
	}
	s.mu.Lock()
	data, ok := s.blobs[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	_, _ = w.Write(data)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	s.hit("upload")
	if d, _, status := s.authDevice(r); d == nil {
		http.Error(w, "refused", status)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.uploads[r.PathValue("id")] = data
	s.notifyLocked()
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// AddBlob stores a blob and returns its id and hex SHA-256.
func (s *Server) AddBlob(data []byte) (id, sha256Hex string) {
	id = protocol.NewID()
	sum := sha256.Sum256(data)
	s.mu.Lock()
	s.blobs[id] = append([]byte(nil), data...)
	s.mu.Unlock()
	return id, hex.EncodeToString(sum[:])
}

// Upload returns the bytes uploaded to a ticket.
func (s *Server) Upload(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.uploads[id]
	return data, ok
}

// EnrollCount and RenewCount return the number of successful calls.
func (s *Server) EnrollCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrolls
}

// RenewCount returns the number of successful renewals.
func (s *Server) RenewCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renews
}

// RenewCountLocked, ConnThumbprintsLocked and CurrentThumbprintLocked are for
// use inside an AwaitCond condition (which already holds the server lock).
func (s *Server) RenewCountLocked() int { return s.renews }

// ConnThumbprintsLocked is ConnThumbprints for use inside AwaitCond.
func (s *Server) ConnThumbprintsLocked(deviceID string) []string {
	if d := s.devices[deviceID]; d != nil {
		return d.connThumbprints
	}
	return nil
}

// CurrentThumbprintLocked is the current thumbprint for use inside AwaitCond.
func (s *Server) CurrentThumbprintLocked(deviceID string) string {
	if d := s.devices[deviceID]; d != nil {
		return d.current
	}
	return ""
}

// Devices returns the ids of all enrolled devices.
func (s *Server) Devices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.devices))
	for id := range s.devices {
		ids = append(ids, id)
	}
	return ids
}

// Revoke revokes a device and closes its connection.
func (s *Server) Revoke(deviceID string) {
	s.mu.Lock()
	d := s.devices[deviceID]
	var conn *websocket.Conn
	if d != nil {
		d.revoked = true
		d.current, d.previous = "", ""
		conn = d.conn
	}
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "revoked")
	}
}

// Thumbprints returns the device's current and previous certificate thumbprints.
func (s *Server) Thumbprints(deviceID string) (current, previous string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[deviceID]; d != nil {
		return d.current, d.previous
	}
	return "", ""
}

// ConnThumbprints returns the certificate thumbprint used by each WebSocket
// connection of the device, in order.
func (s *Server) ConnThumbprints(deviceID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[deviceID]; d != nil {
		return append([]string(nil), d.connThumbprints...)
	}
	return nil
}

// AwaitConnections waits until the device has completed at least n WebSocket
// connections (hello received) in total.
func (s *Server) AwaitConnections(deviceID string, n int, timeout time.Duration) error {
	return s.AwaitCond(timeout, func() bool {
		d := s.devices[deviceID]
		return d != nil && len(d.connThumbprints) >= n && d.conn != nil
	})
}

// Hello returns the last hello of a device.
func (s *Server) Hello(deviceID string) *protocol.Hello {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[deviceID]; d != nil {
		return d.hello
	}
	return nil
}

// Mark returns the number of messages received from the device so far; pass
// it to Await to look only at later messages.
func (s *Server) Mark(deviceID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[deviceID]; d != nil {
		return len(d.messages)
	}
	return 0
}

// Messages returns the messages received from the device starting at index from.
func (s *Server) Messages(deviceID string, from int) []*protocol.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil || from >= len(d.messages) {
		return nil
	}
	return append([]*protocol.Envelope(nil), d.messages[from:]...)
}

// ErrTimeout is returned by the Await helpers.
var ErrTimeout = errors.New("testserver: timed out waiting")

// AwaitCond waits until cond (evaluated under the server lock after every
// state change) is true.
func (s *Server) AwaitCond(timeout time.Duration, cond func() bool) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		ok := cond()
		ch := s.changed
		s.mu.Unlock()
		if ok {
			return nil
		}
		select {
		case <-ch:
		case <-deadline.C:
			return ErrTimeout
		}
	}
}

// AwaitDevice waits for the first enrolled device and returns its id.
func (s *Server) AwaitDevice(timeout time.Duration) (string, error) {
	var id string
	err := s.AwaitCond(timeout, func() bool {
		for k := range s.devices {
			id = k
			return true
		}
		return false
	})
	return id, err
}

// AwaitConnected waits until the device has an open WebSocket that completed hello.
func (s *Server) AwaitConnected(deviceID string, timeout time.Duration) error {
	return s.AwaitCond(timeout, func() bool {
		d := s.devices[deviceID]
		return d != nil && d.conn != nil
	})
}

// Await waits for a message from the device at index >= from that satisfies match.
func (s *Server) Await(deviceID string, from int, timeout time.Duration, match func(*protocol.Envelope) bool) (*protocol.Envelope, error) {
	var found *protocol.Envelope
	next := from
	err := s.AwaitCond(timeout, func() bool {
		d := s.devices[deviceID]
		if d == nil {
			return false
		}
		for ; next < len(d.messages); next++ {
			if match(d.messages[next]) {
				found = d.messages[next]
				return true
			}
		}
		return false
	})
	return found, err
}

// AwaitType waits for the next message of the given type.
func (s *Server) AwaitType(deviceID string, from int, timeout time.Duration, msgType string) (*protocol.Envelope, error) {
	return s.Await(deviceID, from, timeout, func(e *protocol.Envelope) bool { return e.Type == msgType })
}

// Send writes raw bytes to the device's WebSocket.
func (s *Server) Send(deviceID string, data []byte) error {
	s.mu.Lock()
	d := s.devices[deviceID]
	var conn *websocket.Conn
	var ctx context.Context
	if d != nil {
		conn, ctx = d.conn, d.connCtx
	}
	s.mu.Unlock()
	if conn == nil {
		return errors.New("device is not connected")
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, data)
}

// Disconnect closes the device's WebSocket from the server side.
func (s *Server) Disconnect(deviceID string) {
	s.mu.Lock()
	d := s.devices[deviceID]
	var conn *websocket.Conn
	if d != nil {
		conn = d.conn
	}
	s.mu.Unlock()
	if conn != nil {
		_ = conn.CloseNow()
	}
}

// ---- signing helpers ----

// NewNonce returns a fresh base64 nonce (16 random bytes).
func NewNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// Common returns the common signed fields for a command to deviceID that is
// valid from now for five minutes.
func Common(deviceID string) protocol.SignedCommon {
	now := time.Now().UTC()
	return protocol.SignedCommon{DeviceID: deviceID, Nonce: NewNonce(), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
}

// SignEnvelope builds a signed envelope with an arbitrary key (tests use it
// to forge commands with untrusted keys).
func SignEnvelope(priv ed25519.PrivateKey, keyID, msgType string, payload []byte) []byte {
	sig := ed25519.Sign(priv, protocol.SigningInput(msgType, payload))
	sp := base64.StdEncoding.EncodeToString(payload)
	sg := base64.StdEncoding.EncodeToString(sig)
	data, err := json.Marshal(protocol.Envelope{
		Type: msgType, ID: protocol.NewID(), Version: protocol.Version,
		SignedPayload: &sp, Signature: &sg, KeyID: &keyID,
	})
	if err != nil {
		panic(err)
	}
	return data
}

// Sign builds a signed envelope for payload with the server's command key.
func (s *Server) Sign(msgType string, payload any) []byte {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return SignEnvelope(s.cmdPriv, s.KeyID, msgType, raw)
}

// SendSigned signs payload and sends it to the device. It returns the envelope id.
func (s *Server) SendSigned(deviceID, msgType string, payload any) (string, error) {
	data := s.Sign(msgType, payload)
	var env protocol.Envelope
	_ = json.Unmarshal(data, &env)
	return env.ID, s.Send(deviceID, data)
}

// PrivateKey returns the command signing private key (tests only).
func (s *Server) PrivateKey() ed25519.PrivateKey { return s.cmdPriv }
