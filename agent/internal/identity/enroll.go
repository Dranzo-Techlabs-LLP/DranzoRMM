package identity

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// HTTP paths of the enrollment endpoints.
const (
	EnrollPath = "/agent/v1/enroll"
	RenewPath  = "/agent/v1/renew"
)

const maxResponseBytes = 1 << 20

// Errors mapped from the HTTP status of enroll / renew.
var (
	// ErrTokenRejected: 401, the enrollment token is invalid, expired, revoked or used up.
	ErrTokenRejected = errors.New("enrollment token rejected by the server")
	// ErrRateLimited: 429.
	ErrRateLimited = errors.New("rate limited by the server")
	// ErrBadRequest: 400.
	ErrBadRequest = errors.New("server rejected the request as malformed")
	// ErrRevoked: 403, the device is revoked.
	ErrRevoked = errors.New("device is revoked")
)

// EnrollParams are the device facts sent with an enrollment.
type EnrollParams struct {
	Token        string
	Hostname     string
	OS           string
	Arch         string
	AgentVersion string
	MachineID    string
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func postJSON(ctx context.Context, client *http.Client, url string, body any) (*protocol.CertificateResponse, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest:
		return nil, ErrBadRequest
	case http.StatusUnauthorized:
		return nil, ErrTokenRejected
	case http.StatusForbidden:
		return nil, ErrRevoked
	case http.StatusTooManyRequests:
		return nil, ErrRateLimited
	default:
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if len(raw) > maxResponseBytes {
		return nil, errors.New("response too large")
	}
	var out protocol.CertificateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &out, nil
}

// Enroll generates a key pair, sends the CSR with the enrollment token and
// returns the validated identity. client must verify the server against the
// pinned CA only (no client certificate is presented). roots is the same
// pinned pool and is used to validate the issued certificate.
func Enroll(ctx context.Context, client *http.Client, serverURL string, p EnrollParams, roots *x509.CertPool) (*Identity, error) {
	if p.Token == "" {
		return nil, errors.New("no enrollment token")
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	csr, err := NewCSR(key, p.Hostname)
	if err != nil {
		return nil, err
	}
	resp, err := postJSON(ctx, client, serverURL+EnrollPath, protocol.EnrollRequest{
		Token:        p.Token,
		CSR:          string(csr),
		Hostname:     truncate(p.Hostname, 255),
		OS:           p.OS,
		Arch:         p.Arch,
		AgentVersion: truncate(p.AgentVersion, 64),
		MachineID:    truncate(p.MachineID, 128),
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	id, err := fromResponse(key, resp, roots, time.Now())
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	return id, nil
}

// Renew requests a certificate for a NEW key pair over mutual TLS (client
// must present the current certificate). The device id must not change.
func Renew(ctx context.Context, client *http.Client, serverURL string, current *Identity, roots *x509.CertPool) (*Identity, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	csr, err := NewCSR(key, current.DeviceID)
	if err != nil {
		return nil, err
	}
	resp, err := postJSON(ctx, client, serverURL+RenewPath, protocol.RenewRequest{CSR: string(csr)})
	if err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	if resp.DeviceID != current.DeviceID {
		return nil, errors.New("renew: server returned a different device id")
	}
	id, err := fromResponse(key, resp, roots, time.Now())
	if err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	return id, nil
}
