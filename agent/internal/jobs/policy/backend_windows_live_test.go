//go:build windows

package policy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Live Windows test (DRANZO_REAL_WINDOWS=1, run by the Windows verification
// kit, scripts/windows-kit). READ-ONLY: it calls the policy backend's
// readers (USB storage state, password policy via "net accounts" and
// "secedit /export" into a temp file). No remediation is run.

func TestWindowsLivePolicyReaders(t *testing.T) {
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 to run the live Windows tests")
	}
	b, ok := newBackend(platform.New()).(*nativeBackend)
	if !ok {
		t.Fatal("unexpected backend type")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	blocked, detail, err := b.usbStorage(ctx)
	t.Logf("usb storage: blocked=%v detail=%q err=%v", blocked, detail, err)
	if err != nil || detail == "" {
		t.Errorf("usbStorage: %q %v", detail, err)
	}

	pp, err := b.passwordPolicy(ctx)
	t.Logf("password policy: %+v (%s) err=%v", pp, describePassword(pp), err)
	if err != nil {
		t.Fatalf("passwordPolicy: %v", err)
	}
	if pp.Complexity == nil {
		t.Error("password complexity could not be read (secedit /export)")
	}

	self := b.selfAccount()
	t.Logf("self account %q, key %q, domain controller %v", self, b.accountKey(self), isDomainController())
	if self == "" {
		t.Error("selfAccount is empty")
	}
	if b.accountKey(computerName()+`\Alice`) != "alice" {
		t.Errorf("accountKey does not strip the computer name: %q", b.accountKey(computerName()+`\Alice`))
	}
}
