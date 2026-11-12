//go:build windows

package posture

import (
	"context"
	"errors"
	"regexp"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Registry locations of the screen lock settings.
const (
	// PolicySystemKey holds the machine inactivity limit ("Interactive
	// logon: Machine inactivity limit").
	PolicySystemKey        = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	InactivityTimeoutValue = "InactivityTimeoutSecs"

	userSaverPolicyKey = `Software\Policies\Microsoft\Windows\Control Panel\Desktop`
	userSaverKey       = `Control Panel\Desktop`
)

// runJSON runs one of the fixed read-only scripts and returns its JSON.
func (c *Collector) runJSON(ctx context.Context, script string) ([]byte, error) {
	res, err := c.sys.exec.Run(ctx, PowerShell(script))
	if err != nil {
		return nil, err
	}
	data, err := ExtractJSON(res.Stdout)
	if err != nil {
		return nil, errors.New("powershell: " + err.Error() + errTail(res.Stderr))
	}
	return data, nil
}

func (c *Collector) gatherAntivirus(ctx context.Context) ([]protocol.AntivirusProduct, error) {
	data, err := c.runJSON(ctx, PSAntivirus)
	if err != nil {
		return nil, err
	}
	return ParseWindowsAntivirus(data, c.sys.now())
}

func (c *Collector) gatherFirewall(ctx context.Context) (*protocol.FirewallState, error) {
	data, err := c.runJSON(ctx, PSFirewall)
	if err != nil {
		return nil, err
	}
	return ParseWindowsFirewall(data)
}

func (c *Collector) gatherDiskEncryption(ctx context.Context) ([]protocol.DiskEncryption, error) {
	data, err := c.runJSON(ctx, PSBitLocker)
	if err != nil {
		return nil, err
	}
	return ParseBitLocker(data)
}

func (c *Collector) gatherLocalAdmins(ctx context.Context) ([]AdminAccount, error) {
	data, err := c.runJSON(ctx, PSLocalAdmins)
	if err != nil {
		return nil, err
	}
	return ParseWindowsAdmins(data)
}

func (c *Collector) gatherLastPatch(ctx context.Context) (time.Time, error) {
	data, err := c.runJSON(ctx, PSLastPatch)
	if err != nil {
		return time.Time{}, err
	}
	return ParseWindowsLastPatch(data)
}

// MachineInactivitySeconds reads the machine inactivity limit (0 = not set).
func MachineInactivitySeconds() uint64 {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, PolicySystemKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetIntegerValue(InactivityTimeoutValue)
	if err != nil {
		return 0
	}
	return v
}

var sidRe = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,14}$`)

// userScreenSaver reads the screen saver settings from the loaded registry
// hive of a logged-in user (policy values win over the user's own).
func userScreenSaver(sid string) (*ScreenSaver, bool) {
	if !sidRe.MatchString(sid) {
		return nil, false
	}
	values := map[string]string{}
	found := false
	// Later keys do not override: the policy key is read first.
	for _, sub := range []string{userSaverPolicyKey, userSaverKey} {
		k, err := registry.OpenKey(registry.USERS, sid+`\`+sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		found = true
		for _, name := range []string{"ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut"} {
			if _, have := values[name]; have {
				continue
			}
			if v, _, err := k.GetStringValue(name); err == nil {
				values[name] = v
			}
		}
		_ = k.Close()
	}
	if !found {
		return nil, false
	}
	return &ScreenSaver{
		Active:         ParseRegFlag(values["ScreenSaveActive"]),
		Secure:         ParseRegFlag(values["ScreenSaverIsSecure"]),
		TimeoutSeconds: ParseRegSeconds(values["ScreenSaveTimeOut"]),
	}, true
}

func (c *Collector) gatherScreenLock(ctx context.Context) (*protocol.ScreenLock, error) {
	var saver *ScreenSaver
	if u, err := c.plat.ConsoleUser(ctx); err == nil && u != nil {
		if s, ok := userScreenSaver(u.SID); ok {
			saver = s
		}
	} else if err != nil && !errors.Is(err, platform.ErrNoConsoleUser) {
		c.log.Debug("console user not available", "error", err)
	}
	lock, ok := WindowsScreenLock(MachineInactivitySeconds(), saver)
	if !ok {
		return nil, Unsupportedf("no machine inactivity limit is set and no user is logged in whose screen saver settings could be read")
	}
	return lock, nil
}
