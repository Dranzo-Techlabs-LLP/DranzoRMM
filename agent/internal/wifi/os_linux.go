//go:build linux

package wifi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

type nmEnroller struct {
	exec  posture.Exec
	nmcli string
	dir   string
}

// NewEnroller keeps the key, certificate and CA in <state>/wifi and adds a
// NetworkManager connection that trusts the CA for this Wi-Fi only.
func NewEnroller(p platform.Platform, stateDir string) Enroller {
	return nmEnroller{exec: posture.Exec{Platform: p}, nmcli: posture.LookTool("nmcli"), dir: filepath.Join(stateDir, "wifi")}
}

func (n nmEnroller) RequestCSR(context.Context) (string, error) {
	if n.nmcli == "" {
		return "", ErrUnsupported
	}
	if err := fsutil.EnsurePrivateDir(n.dir); err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(n.dir, "client.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "DranzoRMM Wi-Fi"}}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}

func (n nmEnroller) Install(ctx context.Context, ssid, caPem, certPem string) error {
	if n.nmcli == "" {
		return ErrUnsupported
	}
	keyPath := filepath.Join(n.dir, "client.key")
	if _, err := os.Stat(keyPath); err != nil {
		return err
	}
	caPath, certPath := filepath.Join(n.dir, "ca.pem"), filepath.Join(n.dir, "client.pem")
	if err := fsutil.WriteFileAtomic(caPath, []byte(caPem)); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(certPath, []byte(certPem)); err != nil {
		return err
	}
	name := ProfileName(ssid)
	_ = n.Remove(ctx, ssid)
	_, err := n.exec.Output(ctx, posture.Cmd{Path: n.nmcli, Env: []string{"LC_ALL=C"}, Timeout: 30 * time.Second, Args: []string{
		"connection", "add", "type", "wifi", "con-name", name, "ifname", "*", "ssid", ssid,
		"wifi-sec.key-mgmt", "wpa-eap", "802-1x.eap", "tls", "802-1x.identity", "dranzo-device",
		"802-1x.ca-cert", caPath, "802-1x.client-cert", certPath, "802-1x.private-key", keyPath,
		"802-1x.private-key-password-flags", "4", "802-1x.domain-suffix-match", ServerName,
		"connection.autoconnect", "yes",
	}})
	return err
}

func (n nmEnroller) Remove(ctx context.Context, ssid string) error {
	if n.nmcli == "" {
		return ErrUnsupported
	}
	res, err := n.exec.Run(ctx, posture.Cmd{Path: n.nmcli, Args: []string{"connection", "delete", "id", ProfileName(ssid)}, Env: []string{"LC_ALL=C"}})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 && !strings.Contains(res.Stderr, "unknown connection") {
		return &posture.UnsupportedError{Reason: posture.OneLine(res.Combined(), 300)}
	}
	return nil
}
