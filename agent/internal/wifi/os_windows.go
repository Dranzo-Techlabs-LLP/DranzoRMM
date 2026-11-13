//go:build windows

package wifi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

type winEnroller struct {
	exec posture.Exec
	dir  string
}

// NewEnroller creates the key in the machine store with certreq (not
// exportable) and adds a WLAN profile with netsh.
func NewEnroller(p platform.Platform, stateDir string) Enroller {
	return winEnroller{exec: posture.Exec{Platform: p}, dir: filepath.Join(stateDir, "wifi")}
}

func system32(exe string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", exe)
}

// certreqINF requests an RSA 2048 machine key (EAP-TLS on every supported
// Windows version) that never leaves the machine.
const certreqINF = `[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=DranzoRMM Wi-Fi"
KeyAlgorithm = RSA
KeyLength = 2048
HashAlgorithm = sha256
MachineKeySet = TRUE
Exportable = FALSE
ProviderName = "Microsoft Software Key Storage Provider"
RequestType = PKCS10
KeyUsage = 0xa0
FriendlyName = "DranzoRMM Wi-Fi"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
`

func (w winEnroller) run(ctx context.Context, exe string, args ...string) (string, error) {
	return w.exec.Output(ctx, posture.Cmd{Path: system32(exe), Args: args, Timeout: 60 * time.Second})
}

func (w winEnroller) RequestCSR(ctx context.Context) (string, error) {
	if err := fsutil.EnsurePrivateDir(w.dir); err != nil {
		return "", err
	}
	inf, req := filepath.Join(w.dir, "request.inf"), filepath.Join(w.dir, "request.csr")
	_ = os.Remove(req)
	if err := fsutil.WriteFileAtomic(inf, []byte(strings.ReplaceAll(certreqINF, "\n", "\r\n"))); err != nil {
		return "", err
	}
	if _, err := w.run(ctx, "certreq.exe", "-new", "-q", "-machine", inf, req); err != nil {
		return "", err
	}
	b, err := os.ReadFile(req)
	if err != nil {
		return "", err
	}
	return NormalizeCSR(string(b))
}

func (w winEnroller) Install(ctx context.Context, ssid, caPem, certPem string) error {
	ca, _, err := CheckSpec(ssid, caPem, certPem)
	if err != nil {
		return err
	}
	caPath, certPath, profile := filepath.Join(w.dir, "ca.cer"), filepath.Join(w.dir, "client.cer"), filepath.Join(w.dir, "profile.xml")
	if err := fsutil.WriteFileAtomic(caPath, []byte(caPem)); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(certPath, []byte(certPem)); err != nil {
		return err
	}
	// The CA is name-constrained to *.dranzo-radius.invalid and excludes every IP address (checked above).
	if _, err := w.run(ctx, "certutil.exe", "-f", "-addstore", "Root", caPath); err != nil {
		return err
	}
	if _, err := w.run(ctx, "certreq.exe", "-accept", "-machine", "-q", certPath); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(profile, []byte(WindowsProfile(ssid, SHA1Thumbprint(ca)))); err != nil {
		return err
	}
	out, err := w.run(ctx, "netsh.exe", "wlan", "add", "profile", "filename="+profile, "user=all")
	if err != nil && strings.Contains(strings.ToLower(out+err.Error()), "wlansvc") {
		return errors.New("this computer has no Wi-Fi (the WLAN AutoConfig service is not running)")
	}
	return err
}

func (w winEnroller) Remove(ctx context.Context, ssid string) error {
	_, err := w.run(ctx, "netsh.exe", "wlan", "delete", "profile", "name="+ProfileName(ssid))
	return err
}
