//go:build windows

package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/posture"
)

type nativeBackend struct {
	exec posture.Exec
}

func newBackend(p platform.Platform) backend {
	return &nativeBackend{exec: posture.Exec{Platform: p}}
}

func system32(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}

// runFix runs one of the fixed remediation scripts.
func (b *nativeBackend) runFix(ctx context.Context, script string, env ...string) error {
	_, err := b.exec.Output(ctx, posture.PowerShell(script, env...))
	return err
}

func (b *nativeBackend) enableFirewall(ctx context.Context) (string, error) {
	if err := b.runFix(ctx, PSEnableFirewall); err != nil {
		return "", err
	}
	return "ran `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True`", nil
}

func (b *nativeBackend) enableDefender(ctx context.Context) (string, error) {
	if err := b.runFix(ctx, PSEnableDefender); err != nil {
		return "", err
	}
	return "ran `Set-MpPreference -DisableRealtimeMonitoring $false` and made sure the WinDefend service is running", nil
}

// setScreenLockTimeout writes the machine inactivity limit ("Interactive
// logon: Machine inactivity limit"), the machine-wide lock of Windows.
func (b *nativeBackend) setScreenLockTimeout(_ context.Context, seconds int) (string, error) {
	if seconds < MinScreenLockSeconds || seconds > MaxScreenLockSeconds {
		return "", errors.New("timeout out of range")
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, posture.PolicySystemKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open policy key: %w", err)
	}
	defer func() { _ = k.Close() }()
	if err := k.SetDWordValue(posture.InactivityTimeoutValue, uint32(seconds)); err != nil {
		return "", fmt.Errorf("set %s: %w", posture.InactivityTimeoutValue, err)
	}
	return fmt.Sprintf("set the machine inactivity limit (%s) to %d seconds; it applies from the next sign-in", posture.InactivityTimeoutValue, seconds), nil
}

// domainControllerNote explains why a domain controller is not remediated.
const domainControllerNote = "this machine is a domain controller: the setting belongs to the domain and the agent does not change it"

// isDomainController reads the product type from the registry.
func isDomainController() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ProductOptionsKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(ProductTypeValue)
	return err == nil && IsDomainControllerProductType(v)
}

var sidRe = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,14}$`)

// removeAdmin removes one member from the local Administrators group. The
// member travels in an environment variable, never in the script text.
func (b *nativeBackend) removeAdmin(ctx context.Context, a posture.AdminAccount) error {
	if isDomainController() {
		return reportOnlyf("%s", domainControllerNote)
	}
	member := a.Name
	if sidRe.MatchString(a.SID) {
		member = a.SID
	} else if !ValidAccountName(member) {
		return errors.New("account cannot be removed: unusual name and no SID")
	}
	return b.runFix(ctx, PSRemoveAdmin, EnvAdminMember+"="+member)
}

func (b *nativeBackend) selfAccount() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

func computerName() string {
	if n := os.Getenv("COMPUTERNAME"); n != "" {
		return n
	}
	n, _ := os.Hostname()
	return n
}

// accountKey: Windows account names are case-insensitive and local accounts
// may be written with or without the computer prefix.
func (b *nativeBackend) accountKey(name string) string {
	return strings.ToLower(posture.StripLocalPrefix(name, computerName()))
}

func readDWord(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}

func (b *nativeBackend) usbStorage(context.Context) (bool, string, error) {
	var s usbState
	s.Start, s.StartKnown = readDWord(registry.LOCAL_MACHINE, USBStorKey, "Start")
	if v, ok := readDWord(registry.LOCAL_MACHINE, RemovableStorageKey, "Deny_All"); ok && v == 1 {
		s.DenyAll = true
	}
	disks := RemovableStorageKey + `\` + RemovableDisksClass
	if v, ok := readDWord(registry.LOCAL_MACHINE, disks, "Deny_Read"); ok && v == 1 {
		s.DenyRead = true
	}
	if v, ok := readDWord(registry.LOCAL_MACHINE, disks, "Deny_Write"); ok && v == 1 {
		s.DenyWrite = true
	}
	blocked, detail := evalUSB(s)
	return blocked, detail, nil
}

// blockUSBStorage disables the USB mass-storage driver (USBSTOR Start = 4).
func (b *nativeBackend) blockUSBStorage(context.Context) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, USBStorKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open the USBSTOR service key: %w", err)
	}
	defer func() { _ = k.Close() }()
	if err := k.SetDWordValue("Start", USBStorDisabled); err != nil {
		return "", fmt.Errorf("set USBSTOR Start: %w", err)
	}
	return fmt.Sprintf("set USBSTOR Start to %d (driver disabled)", USBStorDisabled), nil
}

func (b *nativeBackend) passwordPolicy(ctx context.Context) (PasswordPolicy, error) {
	out, err := b.exec.Output(ctx, posture.Cmd{Path: system32("net.exe"), Args: []string{"accounts"}})
	if err != nil {
		return PasswordPolicy{}, err
	}
	p, err := ParseNetAccounts(out)
	if err != nil {
		return PasswordPolicy{}, err
	}
	if v, ok := b.complexity(ctx); ok {
		p.Complexity = &v
	}
	return p, nil
}

// complexity exports the security policy (read-only) and reads
// PasswordComplexity from it.
func (b *nativeBackend) complexity(ctx context.Context) (bool, bool) {
	dir, err := os.MkdirTemp("", "dranzo-secpol-")
	if err != nil {
		return false, false
	}
	defer func() { _ = os.RemoveAll(dir) }()
	cfg := filepath.Join(dir, "policy.inf")
	if _, err := b.exec.Output(ctx, posture.Cmd{
		Path:    system32("secedit.exe"),
		Args:    []string{"/export", "/cfg", cfg, "/areas", "SECURITYPOLICY", "/quiet"},
		Timeout: time.Minute,
	}); err != nil {
		return false, false
	}
	data, err := os.ReadFile(cfg)
	if err != nil || len(data) > 4<<20 {
		return false, false
	}
	return ParseSeceditComplexity(data)
}

// setPasswordPolicy tightens the local policy with `net accounts`. The
// arguments are validated integers passed as argv elements.
func (b *nativeBackend) setPasswordPolicy(ctx context.Context, minLength, maxAgeDays *int) (string, error) {
	if minLength == nil && maxAgeDays == nil {
		return "", errors.New("nothing to set")
	}
	if isDomainController() {
		return "", reportOnlyf("%s", domainControllerNote)
	}
	if minLength != nil && (*minLength < MinPasswordLength || *minLength > MaxPasswordLength) {
		return "", errors.New("minimum length out of range")
	}
	if maxAgeDays != nil && (*maxAgeDays < MinPasswordAge || *maxAgeDays > MaxPasswordAge) {
		return "", errors.New("maximum age out of range")
	}
	args := netAccountsArgs(minLength, maxAgeDays)
	if _, err := b.exec.Output(ctx, posture.Cmd{Path: system32("net.exe"), Args: args}); err != nil {
		return "", err
	}
	return "ran `net " + strings.Join(args, " ") + "`", nil
}
