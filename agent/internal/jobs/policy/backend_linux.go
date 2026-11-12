//go:build linux

package policy

import (
	"context"
	"fmt"
	"os/user"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

// cEnv makes tool output locale-independent.
var cEnv = []string{"LC_ALL=C", "LANG=C"}

type nativeBackend struct {
	exec posture.Exec
	// look finds a tool in the fixed system directories ("" if absent).
	look func(names ...string) string
	self func() string
}

func newBackend(p platform.Platform) backend {
	return &nativeBackend{exec: posture.Exec{Platform: p}, look: posture.LookTool, self: currentUser}
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// enableFirewall turns on the firewall that is already installed: ufw, else
// firewalld. It never installs one.
func (b *nativeBackend) enableFirewall(ctx context.Context) (string, error) {
	if ufw := b.look("ufw"); ufw != "" {
		if _, err := b.exec.Output(ctx, posture.Cmd{Path: ufw, Args: []string{"--force", "enable"}, Env: cEnv, Timeout: time.Minute}); err != nil {
			return "", err
		}
		return "ran `ufw --force enable` (ufw denies incoming connections that have no allow rule)", nil
	}
	if b.look("firewall-cmd") != "" {
		systemctl := b.look("systemctl")
		if systemctl == "" {
			return "", reportOnlyf("firewalld is installed but systemctl is not available to start it")
		}
		if _, err := b.exec.Output(ctx, posture.Cmd{Path: systemctl, Args: []string{"enable", "--now", "firewalld"}, Env: cEnv, Timeout: time.Minute}); err != nil {
			return "", err
		}
		return "ran `systemctl enable --now firewalld`", nil
	}
	return "", reportOnlyf("neither ufw nor firewalld is installed and the agent never installs software")
}

func (b *nativeBackend) enableDefender(context.Context) (string, error) {
	return "", reportOnlyf("the agent only re-enables Microsoft Defender on Windows; fix the antivirus in that product")
}

func (b *nativeBackend) setScreenLockTimeout(context.Context, int) (string, error) {
	return "", reportOnlyf("report only on Linux: the screen lock is a per-user desktop setting and the agent does not manage a machine-wide one")
}

// removeAdmin takes the account out of the administrator groups it is a
// supplementary member of (`gpasswd -d user group`). The account stays.
func (b *nativeBackend) removeAdmin(ctx context.Context, a posture.AdminAccount) error {
	if !ValidAccountName(a.Name) || len(a.Groups) == 0 {
		return fmt.Errorf("account cannot be removed by a group edit")
	}
	gpasswd := b.look("gpasswd")
	if gpasswd == "" {
		return reportOnlyf("gpasswd is not installed")
	}
	for _, g := range a.Groups {
		if !isAdminGroup(g) {
			return fmt.Errorf("refusing to edit group %q", g)
		}
		if _, err := b.exec.Output(ctx, posture.Cmd{Path: gpasswd, Args: []string{"-d", a.Name, g}, Env: cEnv}); err != nil {
			return err
		}
	}
	return nil
}

func isAdminGroup(name string) bool {
	for _, g := range posture.LinuxAdminGroups {
		if g == name {
			return true
		}
	}
	return false
}

func (b *nativeBackend) selfAccount() string { return b.self() }

// accountKey: Linux account names are case-sensitive.
func (b *nativeBackend) accountKey(name string) string { return name }

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
