//go:build darwin

package policy

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

// Fixed tool locations on macOS.
const (
	socketFilterFWPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	dseditgroupPath    = "/usr/sbin/dseditgroup"
	adminGroup         = "admin"
)

type nativeBackend struct {
	exec posture.Exec
	self func() string
}

func newBackend(p platform.Platform) backend {
	return &nativeBackend{exec: posture.Exec{Platform: p}, self: currentUser}
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// enableFirewall turns the Application Firewall on (needs root).
func (b *nativeBackend) enableFirewall(ctx context.Context) (string, error) {
	if _, err := b.exec.Output(ctx, posture.Cmd{Path: socketFilterFWPath, Args: []string{"--setglobalstate", "on"}, Timeout: time.Minute}); err != nil {
		return "", err
	}
	return "ran `socketfilterfw --setglobalstate on`", nil
}

func (b *nativeBackend) enableDefender(context.Context) (string, error) {
	return "", reportOnlyf("the agent only re-enables Microsoft Defender on Windows; fix the antivirus in that product")
}

func (b *nativeBackend) setScreenLockTimeout(context.Context, int) (string, error) {
	return "", reportOnlyf("report only on macOS: a machine-wide screen lock needs an MDM configuration profile")
}

// removeAdmin takes a user out of the admin group (`dseditgroup -o edit -d
// <user> -t user admin`, needs root). The account stays.
func (b *nativeBackend) removeAdmin(ctx context.Context, a posture.AdminAccount) error {
	if !ValidAccountName(a.Name) {
		return errors.New("account cannot be removed by a group edit")
	}
	_, err := b.exec.Output(ctx, posture.Cmd{Path: dseditgroupPath, Args: []string{"-o", "edit", "-d", a.Name, "-t", "user", adminGroup}})
	return err
}

func (b *nativeBackend) selfAccount() string { return b.self() }

// accountKey: macOS account names are compared case-insensitively, as the
// directory service does.
func (b *nativeBackend) accountKey(name string) string { return strings.ToLower(name) }

func (b *nativeBackend) usbStorage(context.Context) (bool, string, error) {
	return false, "", posture.Unsupportedf("usb.storage.blocked is available on Windows only")
}

func (b *nativeBackend) blockUSBStorage(context.Context) (string, error) {
	return "", posture.Unsupportedf("usb.storage.blocked is available on Windows only")
}

func (b *nativeBackend) passwordPolicy(context.Context) (PasswordPolicy, error) {
	return PasswordPolicy{}, posture.Unsupportedf("password.policy is available on Windows only")
}

func (b *nativeBackend) setPasswordPolicy(context.Context, *int, *int) (string, error) {
	return "", posture.Unsupportedf("password.policy is available on Windows only")
}
