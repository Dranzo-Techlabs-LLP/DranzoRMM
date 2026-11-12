package transport_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/identity"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
	"github.com/dranzo/dranzormm/agent/internal/transport"
)

func newServer(t *testing.T, opts testserver.Options) *testserver.Server {
	t.Helper()
	s, err := testserver.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func pool(t *testing.T, s *testserver.Server) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(s.CAPEM) {
		t.Fatal("bad CA PEM")
	}
	return p
}

func enroll(t *testing.T, s *testserver.Server) *identity.Identity {
	t.Helper()
	roots := pool(t, s)
	client := transport.NewHTTPClient(transport.NewTLSConfig(roots, nil), 10*time.Second)
	id, err := identity.Enroll(context.Background(), client, s.URL, identity.EnrollParams{
		Token: s.Token, Hostname: "test", OS: "linux", Arch: "amd64", AgentVersion: "test", MachineID: "m",
	}, roots)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func clientFor(t *testing.T, s *testserver.Server, id *identity.Identity) *transport.Client {
	roots := pool(t, s)
	return &transport.Client{
		ServerURL: s.URL,
		TLS: func() *tls.Config {
			return transport.NewTLSConfig(roots, func() *tls.Certificate { return &id.TLS })
		},
	}
}

func TestTLSPolicy(t *testing.T) {
	cfg := transport.NewTLSConfig(x509.NewCertPool(), nil)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("certificate verification must never be disabled")
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs must be the pinned pool, never nil (nil means the OS trust store)")
	}
	// A nil pool must not silently fall back to the system roots.
	if transport.NewTLSConfig(nil, nil).RootCAs == nil {
		t.Fatal("nil roots must become an empty pool")
	}
}

func TestDialExchangeAndLimits(t *testing.T) {
	s := newServer(t, testserver.Options{})
	id := enroll(t, s)
	c := clientFor(t, s, id)
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(1000, "")
	hello, _ := protocol.NewEnvelope(protocol.TypeHello, protocol.Hello{AgentVersion: "t", ProtocolVersion: 1})
	if err := conn.Send(context.Background(), hello); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.ParseEnvelope(data)
	if err != nil || env.Type != protocol.TypeHelloAck {
		t.Fatalf("expected hello.ack, got %v %v", env, err)
	}
	// Oversized outgoing messages are refused locally.
	if err := conn.Send(context.Background(), make([]byte, protocol.MaxMessageBytes+1)); err == nil {
		t.Fatal("oversized message accepted")
	}
	// An incoming message above 2 MiB closes the connection instead of being buffered.
	go func() {
		// The write blocks until the peer reads (or gives up), so it runs concurrently.
		_ = s.Send(id.DeviceID, []byte(`{"type":"error","id":"x","version":1,"payload":{"message":"`+strings.Repeat("A", protocol.MaxMessageBytes)+`"}}`))
	}()
	if _, err := conn.Read(ctx); err == nil {
		t.Fatal("oversized incoming message was accepted")
	}
	select {
	case <-conn.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed after an oversized message")
	}
	if err := conn.Send(context.Background(), hello); !errors.Is(err, transport.ErrConnClosed) {
		t.Fatalf("send on closed connection: %v", err)
	}
}

func TestRefusesServerNotFromPinnedCA(t *testing.T) {
	trusted := newServer(t, testserver.Options{})
	other := newServer(t, testserver.Options{}) // different throwaway CA
	id := enroll(t, trusted)

	// Pinned to "trusted" but pointed at "other".
	c := clientFor(t, trusted, id)
	c.ServerURL = other.URL
	_, err := c.Dial(context.Background())
	if err == nil {
		t.Fatal("connected to a server whose certificate is not from the pinned CA")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) && !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("expected an unknown-authority error, got %v", err)
	}
	if other.Hits("ws") != 0 {
		t.Fatal("the request reached the untrusted server")
	}

	// Same for the HTTPS helper (enrollment).
	roots := pool(t, trusted)
	client := transport.NewHTTPClient(transport.NewTLSConfig(roots, nil), 5*time.Second)
	if _, err := identity.Enroll(context.Background(), client, other.URL, identity.EnrollParams{Token: other.Token}, roots); err == nil {
		t.Fatal("enrolled against an untrusted server")
	}
	if other.Hits("enroll") != 0 {
		t.Fatal("the enrollment token was sent to an untrusted server")
	}
}

func TestHostnameVerificationIsOn(t *testing.T) {
	s := newServer(t, testserver.Options{})
	roots := pool(t, s)
	cfg := transport.NewTLSConfig(roots, nil)
	cfg.ServerName = "rmm.attacker.example" // the certificate is for localhost / 127.0.0.1
	conn, err := tls.Dial("tcp", strings.TrimPrefix(s.URL, "https://"), cfg)
	if err == nil {
		_ = conn.Close()
		t.Fatal("handshake succeeded for the wrong host name")
	}
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("expected a hostname error, got %v", err)
	}
}

func TestRevokedDeviceGets403(t *testing.T) {
	s := newServer(t, testserver.Options{})
	id := enroll(t, s)
	s.Revoke(id.DeviceID)
	_, err := clientFor(t, s, id).Dial(context.Background())
	if !errors.Is(err, transport.ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestRunReconnectsWithBackoff(t *testing.T) {
	s := newServer(t, testserver.Options{})
	id := enroll(t, s)
	c := clientFor(t, s, id)

	var mu sync.Mutex
	var delays []time.Duration
	c.Backoff = transport.NewBackoff()
	c.Backoff.Rand = func(n int64) int64 { return n - 1 }
	c.Sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		delays = append(delays, d)
		mu.Unlock()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connections := make(chan struct{}, 16)
	go func() {
		_ = c.Run(ctx, func(ctx context.Context, conn *transport.Conn) error {
			hello, _ := protocol.NewEnvelope(protocol.TypeHello, protocol.Hello{})
			if err := conn.Send(ctx, hello); err != nil {
				return err
			}
			connections <- struct{}{}
			for {
				if _, err := conn.Read(ctx); err != nil {
					return err
				}
			}
		})
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-connections:
		case <-time.After(10 * time.Second):
			t.Fatalf("connection %d not established", i)
		}
		if err := s.AwaitConnections(id.DeviceID, i+1, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		s.Disconnect(id.DeviceID)
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if len(delays) < 2 || delays[0] != time.Second || delays[1] != 2*time.Second {
		t.Fatalf("expected exponential reconnect delays (1s, 2s, ...), got %v", delays)
	}
}

func TestBlobDownloadVerifiesHashAndSize(t *testing.T) {
	s := newServer(t, testserver.Options{})
	id := enroll(t, s)
	roots := pool(t, s)
	blobs := &transport.BlobClient{ServerURL: s.URL, TLS: func() *tls.Config {
		return transport.NewTLSConfig(roots, func() *tls.Certificate { return &id.TLS })
	}}
	content := bytes.Repeat([]byte("package-bytes-"), 5000)
	blobID, sum := s.AddBlob(content)
	dir := t.TempDir()

	good := filepath.Join(dir, "good.bin")
	if err := blobs.DownloadFile(context.Background(), blobID, good, int64(len(content)), sum); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(good); !bytes.Equal(got, content) {
		t.Fatal("downloaded content differs")
	}

	bad := filepath.Join(dir, "bad.bin")
	wrong := strings.Repeat("0", 64)
	if err := blobs.DownloadFile(context.Background(), blobID, bad, int64(len(content)), wrong); !errors.Is(err, transport.ErrHashMismatch) {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("a file with a wrong hash must not be left on disk")
	}
	if err := blobs.DownloadFile(context.Background(), blobID, bad, int64(len(content))-1, sum); !errors.Is(err, transport.ErrSizeMismatch) {
		t.Fatalf("expected size mismatch, got %v", err)
	}
	if err := blobs.DownloadFile(context.Background(), "../../etc/passwd", bad, 1, sum); err == nil {
		t.Fatal("invalid blob id accepted")
	}

	// Upload.
	uploadID := protocol.NewID()
	if err := blobs.Upload(context.Background(), uploadID, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Upload(uploadID); !ok || !bytes.Equal(got, content) {
		t.Fatal("upload did not arrive intact")
	}

	// Without a client certificate the blob endpoint refuses.
	anon := &transport.BlobClient{ServerURL: s.URL, TLS: func() *tls.Config { return transport.NewTLSConfig(roots, nil) }}
	if err := anon.DownloadFile(context.Background(), blobID, filepath.Join(dir, "anon.bin"), int64(len(content)), sum); err == nil {
		t.Fatal("blob served without a client certificate")
	}
}
