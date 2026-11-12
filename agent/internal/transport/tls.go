// Package transport implements the agent's outbound connectivity: the
// WebSocket control connection over mutual TLS with a pinned CA, reconnect
// with exponential backoff and full jitter, and the HTTPS helper for blob
// download / upload. Every connection uses the same TLS policy.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"
)

// CertSource returns the current device certificate (nil before enrollment).
// It is consulted on every TLS handshake, so a renewed certificate is used
// by the next connection without a restart.
type CertSource func() *tls.Certificate

// NewTLSConfig builds the TLS policy used for every connection to the server:
//   - RootCAs is ONLY the pinned DranzoRMM CA pool; the OS trust store is never consulted;
//   - hostname verification stays enabled (InsecureSkipVerify is never set);
//   - TLS 1.2 minimum;
//   - the device certificate is presented when the server asks for one.
//
// roots must not be nil: a nil pool would make crypto/tls fall back to the
// system roots, so that case is turned into a handshake failure.
func NewTLSConfig(roots *x509.CertPool, cert CertSource) *tls.Config {
	if roots == nil {
		// An empty (non-nil) pool trusts nothing: fail closed.
		roots = x509.NewCertPool()
	}
	cfg := &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if cert != nil {
			if c := cert(); c != nil {
				return c, nil
			}
		}
		// No identity yet (enrollment): present no certificate.
		return &tls.Certificate{}, nil
	}
	return cfg
}

// NewHTTPClient returns an HTTP client bound to cfg. It follows no redirects
// and uses no proxy and no shared connection pool, so each call observes the
// current trust store and device certificate.
func NewHTTPClient(cfg *tls.Config, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:        cfg,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    30 * time.Second,
		ResponseHeaderTimeout:  60 * time.Second,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errNoRedirects
		},
	}
}

var errNoRedirects = errors.New("redirects are not followed")
