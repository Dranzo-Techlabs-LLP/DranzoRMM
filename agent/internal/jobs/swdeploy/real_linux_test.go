//go:build linux

package swdeploy_test

import (
	"context"
	"os"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs/swdeploy"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
)

// TestRealInstallRemove installs and removes a real package through the
// handlers with the real platform (opt-in: DRANZO_REAL_LINUX=1 and
// DRANZO_REAL_MANAGER=apt|dnf, DRANZO_REAL_PACKAGE, run as root in a
// throwaway container).
func TestRealInstallRemove(t *testing.T) {
	if os.Getenv("DRANZO_REAL_LINUX") != "1" {
		t.Skip("set DRANZO_REAL_LINUX=1 to install real packages on this system")
	}
	manager, pkg := os.Getenv("DRANZO_REAL_MANAGER"), os.Getenv("DRANZO_REAL_PACKAGE")
	plat := platform.New()
	for _, uninstall := range []bool{false, true} {
		h := swdeploy.NewInstall()
		if uninstall {
			h = swdeploy.NewUninstall()
		}
		job := swtest.NewJob(context.Background(), plat, t.TempDir(), protocol.SoftwareSpec{Manager: manager, PackageID: pkg})
		res := h.Handle(job.JobContext)
		out := job.Out.String()
		if len(out) > 1500 {
			out = "..." + out[len(out)-1500:]
		}
		t.Logf("uninstall=%v status=%s message=%q result=%+v\n%s", uninstall, res.Status, res.Message, res.Result, out)
		r, ok := res.Result.(protocol.InstallResult)
		if res.Status != protocol.StatusSucceeded || !ok || r.Installed == uninstall || (!uninstall && r.Version == "") {
			t.Fatalf("uninstall=%v: status %s (%s), result %+v, stderr %s", uninstall, res.Status, res.Message, res.Result, job.ErrOut.String())
		}
	}
	// The other Linux manager is "not installed" here, and an injection is rejected.
	other := "dnf"
	if manager == "dnf" {
		other = "apt"
	}
	for spec, want := range map[protocol.SoftwareSpec]string{
		{Manager: other, PackageID: pkg}:             protocol.StatusUnsupported,
		{Manager: "winget", PackageID: "7zip.7zip"}:  protocol.StatusUnsupported,
		{Manager: manager, PackageID: "x; rm -rf /"}: protocol.StatusRejected,
	} {
		job := swtest.NewJob(context.Background(), plat, t.TempDir(), spec)
		if res := swdeploy.NewInstall().Handle(job.JobContext); res.Status != want {
			t.Errorf("%+v: status %s (%s), want %s", spec, res.Status, res.Message, want)
		}
	}
}
