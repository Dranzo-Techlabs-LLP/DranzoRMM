package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Blob transfer errors.
var (
	ErrHashMismatch = errors.New("blob SHA-256 does not match the signed command")
	ErrSizeMismatch = errors.New("blob size does not match the signed command")
)

// MaxBlobBytes bounds any single blob download (4 GiB).
const MaxBlobBytes = 4 << 30

// BlobClient downloads blobs and uploads files over the pinned mTLS channel
// (PROTOCOL.md section 8). The SHA-256 and size always come from a signed command.
type BlobClient struct {
	ServerURL string
	TLS       func() *tls.Config
	// Timeout bounds one whole transfer (default 2 hours).
	Timeout time.Duration
}

func (b *BlobClient) client() *http.Client {
	timeout := b.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Hour
	}
	return NewHTTPClient(b.TLS(), timeout)
}

// Download streams blob blobID into dst, enforcing sizeBytes and verifying
// sha256Hex. The data written to dst MUST NOT be used unless nil is returned.
func (b *BlobClient) Download(ctx context.Context, blobID string, dst io.Writer, sizeBytes int64, sha256Hex string) error {
	if !protocol.ValidUUID(blobID) {
		return errors.New("invalid blob id")
	}
	if !protocol.ValidSHA256Hex(sha256Hex) {
		return errors.New("invalid sha256")
	}
	if sizeBytes < 0 || sizeBytes > MaxBlobBytes {
		return errors.New("invalid blob size")
	}
	want, _ := hex.DecodeString(sha256Hex)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.ServerURL+"/agent/v1/blobs/"+blobID, nil)
	if err != nil {
		return err
	}
	resp, err := b.client().Do(req)
	if err != nil {
		return fmt.Errorf("download blob: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download blob: HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != sizeBytes {
		return ErrSizeMismatch
	}
	h := sha256.New()
	// Read at most sizeBytes+1 so an oversized body is detected without buffering it.
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(resp.Body, sizeBytes+1))
	if err != nil {
		return fmt.Errorf("download blob: %w", err)
	}
	if n != sizeBytes {
		return ErrSizeMismatch
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return ErrHashMismatch
	}
	return nil
}

// DownloadFile downloads a blob to a new owner-only file at destPath. The
// file is removed again on any failure, including a hash or size mismatch.
func (b *BlobClient) DownloadFile(ctx context.Context, blobID, destPath string, sizeBytes int64, sha256Hex string) (err error) {
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create download file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(destPath)
		}
	}()
	if err = b.Download(ctx, blobID, f, sizeBytes, sha256Hex); err != nil {
		return err
	}
	return f.Sync()
}

// Upload sends sizeBytes bytes of src to the one-time upload ticket uploadID.
func (b *BlobClient) Upload(ctx context.Context, uploadID string, src io.Reader, sizeBytes int64) error {
	if !protocol.ValidUUID(uploadID) {
		return errors.New("invalid upload id")
	}
	if sizeBytes < 0 {
		return errors.New("invalid upload size")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, b.ServerURL+"/agent/v1/uploads/"+uploadID, io.LimitReader(src, sizeBytes))
	if err != nil {
		return err
	}
	req.ContentLength = sizeBytes
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := b.client().Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("upload: HTTP status %d", resp.StatusCode)
	}
	return nil
}
