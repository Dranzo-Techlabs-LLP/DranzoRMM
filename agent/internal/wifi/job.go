package wifi

import (
	"context"
	"errors"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ErrUnsupported means 802.1X enrollment is not available on this OS.
var ErrUnsupported = errors.New("802.1X Wi-Fi enrollment is not available on this operating system")

// Enroller is the per-OS side.
type Enroller interface {
	// RequestCSR creates (or replaces) the device's Wi-Fi key and returns a PEM CSR.
	RequestCSR(ctx context.Context) (string, error)
	// Install trusts the CA for this Wi-Fi only where the OS allows, installs the
	// certificate and adds the Wi-Fi profile.
	Install(ctx context.Context, ssid, caPem, certPem string) error
	// Remove deletes the Wi-Fi profile.
	Remove(ctx context.Context, ssid string) error
}

func result(err error) jobs.Result {
	if errors.Is(err, ErrUnsupported) {
		return jobs.Unsupported("%v", err)
	}
	return jobs.Failed("%v", err)
}

// Handlers returns the network.cert.request, network.wifi.install and network.wifi.remove kinds.
func Handlers(e Enroller) map[string]jobs.Handler {
	return map[string]jobs.Handler{
		protocol.KindNetworkCertReq: jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
			csr, err := e.RequestCSR(jc.Ctx)
			if err != nil {
				return result(err)
			}
			return jobs.SucceededWith(protocol.NetworkCertResult{CSR: csr})
		}),
		protocol.KindWifiInstall: jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
			var spec protocol.WifiInstallSpec
			if err := jc.DecodeSpec(&spec); err != nil {
				return jobs.Rejected("%v", err)
			}
			if _, _, err := CheckSpec(spec.SSID, spec.CAPem, spec.CertPem); err != nil {
				return jobs.Rejected("%v", err)
			}
			if err := e.Install(jc.Ctx, spec.SSID, spec.CAPem, spec.CertPem); err != nil {
				return result(err)
			}
			return jobs.SucceededWith(protocol.WifiInstallResult{Installed: true})
		}),
		protocol.KindWifiRemove: jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
			var spec protocol.WifiRemoveSpec
			if err := jc.DecodeSpec(&spec); err != nil {
				return jobs.Rejected("%v", err)
			}
			if err := ValidSSID(spec.SSID); err != nil {
				return jobs.Rejected("%v", err)
			}
			if err := e.Remove(jc.Ctx, spec.SSID); err != nil {
				return result(err)
			}
			return jobs.Succeeded()
		}),
	}
}
