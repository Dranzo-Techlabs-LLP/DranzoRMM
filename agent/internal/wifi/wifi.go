// Package wifi enrolls a device for 802.1X (EAP-TLS) office Wi-Fi: a key and
// CSR made on the device (network.cert.request) and the Wi-Fi profile with
// the issued certificate (network.wifi.install / network.wifi.remove).
//
// Validation and the Windows profile XML are pure functions in this untagged
// file; the OS files run fixed tools (certreq, certutil, netsh, nmcli).
package wifi

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // Windows identifies trusted root CAs by their SHA-1 thumbprint; not used for security
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// ServerName is the RADIUS server name the profile accepts (matches the
// name constraint of the DranzoRMM network CA).
const ServerName = "radius.dranzo-radius.invalid"

// ProfileName is the visible name of the Wi-Fi profile DranzoRMM adds.
func ProfileName(ssid string) string { return "DranzoRMM " + ssid }

// ValidSSID checks an SSID from the server: 1-32 bytes, printable.
func ValidSSID(s string) error {
	if len(s) == 0 || len(s) > 32 {
		return errors.New("the SSID must be 1-32 bytes")
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return errors.New("the SSID contains a control character")
		}
	}
	if strings.HasPrefix(s, "-") {
		return errors.New("the SSID must not start with -")
	}
	return nil
}

// ParseCert reads one PEM certificate; caMustBeCA requires a CA certificate.
func ParseCert(pemText string, caMustBeCA bool) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if c.IsCA != caMustBeCA {
		if caMustBeCA {
			return nil, errors.New("the CA certificate is not a CA")
		}
		return nil, errors.New("the client certificate must not be a CA")
	}
	return c, nil
}

// CheckSpec validates an install spec: SSID, a CA that is name-constrained to
// the DranzoRMM RADIUS domain (so trusting it cannot vouch for websites), and a
// client certificate issued by that CA for client authentication.
func CheckSpec(ssid, caPem, certPem string) (*x509.Certificate, *x509.Certificate, error) {
	if err := ValidSSID(ssid); err != nil {
		return nil, nil, err
	}
	ca, err := ParseCert(caPem, true)
	if err != nil {
		return nil, nil, fmt.Errorf("CA: %w", err)
	}
	if !ca.PermittedDNSDomainsCritical || len(ca.PermittedDNSDomains) != 1 || ca.PermittedDNSDomains[0] != "dranzo-radius.invalid" || len(ca.ExcludedIPRanges) < 2 {
		return nil, nil, errors.New("CA: not a DranzoRMM network CA (name constraints missing)")
	}
	leaf, err := ParseCert(certPem, false)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate: %w", err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return nil, nil, fmt.Errorf("certificate not issued by the CA: %w", err)
	}
	clientAuth := false
	for _, u := range leaf.ExtKeyUsage {
		clientAuth = clientAuth || u == x509.ExtKeyUsageClientAuth
	}
	if !clientAuth {
		return nil, nil, errors.New("certificate is not for client authentication")
	}
	return ca, leaf, nil
}

// SHA1Thumbprint formats a certificate's SHA-1 hash the way Windows profiles
// list trusted root CAs ("ab cd ef ...").
func SHA1Thumbprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw) //nolint:gosec // identifier only
	h := hex.EncodeToString(sum[:])
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, " ")
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// WindowsProfile returns the WLAN profile XML for EAP-TLS with the machine
// certificate, validating the RADIUS server name and the DranzoRMM network CA.
func WindowsProfile(ssid, caThumbprint string) string {
	name := xmlText(ssid)
	return `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>` + xmlText(ProfileName(ssid)) + `</name>
	<SSIDConfig><SSID><name>` + name + `</name></SSID></SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>
			<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
				<authMode>machine</authMode>
				<EAPConfig>
					<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
						<EapMethod>
							<Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
							<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
							<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
							<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
						</EapMethod>
						<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
							<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
								<Type>13</Type>
								<EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
									<CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource>
									<ServerValidation>
										<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
										<ServerNames>` + ServerName + `</ServerNames>
										<TrustedRootCA>` + caThumbprint + `</TrustedRootCA>
									</ServerValidation>
									<DifferentUsername>false</DifferentUsername>
									<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
									<AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>
								</EapType>
							</Eap>
						</Config>
					</EapHostConfig>
				</EAPConfig>
			</OneX>
		</security>
	</MSM>
</WLANProfile>
`
}

// NormalizeCSR turns certreq's "NEW CERTIFICATE REQUEST" (or bare base64)
// output into a standard PEM CERTIFICATE REQUEST, checking it parses.
func NormalizeCSR(out string) (string, error) {
	text := strings.ReplaceAll(out, "\r", "")
	if block, _ := pem.Decode([]byte(text)); block != nil {
		if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes})), nil
	}
	return "", errors.New("no certificate request found")
}
