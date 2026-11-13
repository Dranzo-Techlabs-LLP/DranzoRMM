package wifi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The fixtures were issued by the server's NetworkCertificateAuthority.
func TestCheckSpecAcceptsServerIssuedCertificates(t *testing.T) {
	ca, leaf, err := CheckSpec("Dranzo-Office", read(t, "server-ca.pem"), read(t, "server-client.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(leaf.Subject.String(), "O=DranzoRMM Wi-Fi") || ca.PermittedDNSDomains[0] != "dranzo-radius.invalid" {
		t.Errorf("leaf %s ca %v", leaf.Subject, ca.PermittedDNSDomains)
	}
	if got := SHA1Thumbprint(ca); len(got) != 59 || strings.Count(got, " ") != 19 {
		t.Errorf("thumbprint %q", got)
	}
}

func TestCheckSpecRefusesWrongInput(t *testing.T) {
	ca, client, radius := read(t, "server-ca.pem"), read(t, "server-client.pem"), read(t, "server-radius.pem")
	cases := map[string][3]string{
		"empty ssid":            {"", ca, client},
		"long ssid":             {strings.Repeat("x", 33), ca, client},
		"control char":          {"a\nb", ca, client},
		"client as CA":          {"Office", client, client},
		"server cert as client": {"Office", ca, radius},
		"two certs":             {"Office", ca + ca, client},
		"garbage":               {"Office", "nope", client},
	}
	for name, c := range cases {
		if _, _, err := CheckSpec(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWindowsProfileIsValidXMLAndEscapesTheSSID(t *testing.T) {
	x := WindowsProfile(`Caf<é> & "Co"`, "ab cd")
	var v struct {
		Name string `xml:"name"`
		SSID struct {
			SSID struct {
				Name string `xml:"name"`
			} `xml:"SSID"`
		} `xml:"SSIDConfig"`
	}
	if err := xml.Unmarshal([]byte(x), &v); err != nil {
		t.Fatal(err)
	}
	if v.SSID.SSID.Name != `Caf<é> & "Co"` || v.Name != `DranzoRMM Caf<é> & "Co"` {
		t.Errorf("%+v", v)
	}
	for _, want := range []string{"<ServerNames>radius.dranzo-radius.invalid</ServerNames>", "<TrustedRootCA>ab cd</TrustedRootCA>", "<authMode>machine</authMode>", "<Type>13</Type>"} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestNormalizeCSR(t *testing.T) {
	if _, err := NormalizeCSR("nothing"); err == nil {
		t.Error("garbage accepted")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "DranzoRMM Wi-Fi"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	// certreq writes the legacy label and CRLF line ends.
	legacy := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: der})), "\n", "\r\n")
	got, err := NormalizeCSR(legacy)
	if err != nil || !strings.HasPrefix(got, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("%q %v", got, err)
	}
	der[len(der)-1] ^= 0xff
	if _, err := NormalizeCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der[:len(der)-10]}))); err == nil {
		t.Error("broken CSR accepted")
	}
}

type fakeEnroller struct {
	installed []string
	err       error
}

func (f *fakeEnroller) RequestCSR(context.Context) (string, error) { return "csr", f.err }
func (f *fakeEnroller) Install(_ context.Context, ssid, _, _ string) error {
	f.installed = append(f.installed, ssid)
	return f.err
}
func (f *fakeEnroller) Remove(context.Context, string) error { return f.err }

func run(t *testing.T, h jobs.Handler, spec string) jobs.Result {
	t.Helper()
	return h.Handle(&jobs.JobContext{Ctx: context.Background(), Spec: []byte(spec)})
}

func TestHandlers(t *testing.T) {
	f := &fakeEnroller{}
	hs := Handlers(f)
	if r := run(t, hs[protocol.KindNetworkCertReq], `{}`); r.Status != protocol.StatusSucceeded || r.Result.(protocol.NetworkCertResult).CSR != "csr" {
		t.Errorf("cert request %+v", r)
	}
	ok := `{"ssid":"Office","caPem":` + quote(read(t, "server-ca.pem")) + `,"certPem":` + quote(read(t, "server-client.pem")) + `}`
	if r := run(t, hs[protocol.KindWifiInstall], ok); r.Status != protocol.StatusSucceeded || len(f.installed) != 1 {
		t.Errorf("install %+v", r)
	}
	bad := `{"ssid":"Office","caPem":` + quote(read(t, "server-client.pem")) + `,"certPem":` + quote(read(t, "server-client.pem")) + `}`
	if r := run(t, hs[protocol.KindWifiInstall], bad); r.Status != protocol.StatusRejected || len(f.installed) != 1 {
		t.Errorf("bad install %+v", r)
	}
	f.err = ErrUnsupported
	if r := run(t, hs[protocol.KindNetworkCertReq], `{}`); r.Status != protocol.StatusUnsupported {
		t.Errorf("unsupported %+v", r)
	}
	f.err = errors.New("netsh failed")
	if r := run(t, hs[protocol.KindWifiRemove], `{"ssid":"Office"}`); r.Status != protocol.StatusFailed {
		t.Errorf("failed %+v", r)
	}
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	return `"` + r.Replace(s) + `"`
}
