//go:build linux

package pkginstall_test

import (
	"context"
	"os"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/jobs/pkginstall"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software/swtest"
)

// TestRealPackageInstall installs a real local .deb / .rpm through
// package.install (the "blob" is served by the fake blob client from the
// file DRANZO_REAL_PKG_FILE) with a detection rule, then removes it through
// package.uninstall. Opt-in, run as root in a throwaway container.
func TestRealPackageInstall(t *testing.T) {
	if os.Getenv("DRANZO_REAL_LINUX") != "1" || os.Getenv("DRANZO_REAL_PKG_FILE") == "" {
		t.Skip("set DRANZO_REAL_LINUX=1 and DRANZO_REAL_PKG_FILE to install a real package file")
	}
	data, err := os.ReadFile(os.Getenv("DRANZO_REAL_PKG_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	typ, name := os.Getenv("DRANZO_REAL_PKG_TYPE"), os.Getenv("DRANZO_REAL_PKG_NAME")
	detType := "dpkg"
	removeCmd := []string{"apt-get", "-y", "remove", name}
	if typ == "rpm" {
		detType = "rpm"
		removeCmd = []string{"dnf", "-y", "remove", name}
	}
	det := &protocol.Detection{Type: detType, Key: name, MinVersion: "1.0"}
	plat := platform.New()
	blobs := &swtest.Blobs{Content: data}
	spec := protocol.PackageInstallSpec{BlobID: "11111111-2222-4333-8444-555555555555", SHA256: swtest.SHA256(data), SizeBytes: int64(len(data)),
		FileName: "dranzo-test-pkg", Type: typ, Detection: det}

	// A corrupted download is rejected and never installed.
	bad := spec
	bad.SHA256 = swtest.SHA256([]byte("other"))
	job := swtest.NewJob(context.Background(), plat, t.TempDir(), bad)
	job.Blobs = blobs
	if res := pkginstall.NewInstall().Handle(job.JobContext); res.Status != protocol.StatusRejected {
		t.Fatalf("hash mismatch: %s (%s)", res.Status, res.Message)
	}

	for round := 0; round < 2; round++ {
		job = swtest.NewJob(context.Background(), plat, t.TempDir(), spec)
		job.Blobs = blobs
		res := pkginstall.NewInstall().Handle(job.JobContext)
		t.Logf("install round %d: %s %q %+v\n%s", round, res.Status, res.Message, res.Result, job.Out.String())
		r, ok := res.Result.(protocol.InstallResult)
		if res.Status != protocol.StatusSucceeded || !ok || !r.Installed || r.Version == "" {
			t.Fatalf("install: %s (%s) %+v stderr %s", res.Status, res.Message, res.Result, job.ErrOut.String())
		}
		if round == 1 && res.Message != "already installed" {
			t.Fatalf("second install did not short-circuit: %q", res.Message)
		}
	}
	job = swtest.NewJob(context.Background(), plat, t.TempDir(), protocol.PackageUninstallSpec{Type: typ, UninstallCommand: removeCmd, Detection: det})
	res := pkginstall.NewUninstall().Handle(job.JobContext)
	t.Logf("uninstall: %s %q %+v", res.Status, res.Message, res.Result)
	if r, ok := res.Result.(protocol.PackageUninstallResult); res.Status != protocol.StatusSucceeded || !ok || r.Installed {
		t.Fatalf("uninstall: %s (%s) %+v stderr %s", res.Status, res.Message, res.Result, job.ErrOut.String())
	}
}
