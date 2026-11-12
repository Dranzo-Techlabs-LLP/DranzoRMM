//go:build darwin

package posture

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Fixed tool and file locations on macOS.
const (
	spctlPath          = "/usr/sbin/spctl"
	socketFilterFWPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	fdesetupPath       = "/usr/bin/fdesetup"
	dsclPath           = "/usr/bin/dscl"
	sysadminctlPath    = "/usr/sbin/sysadminctl"
	defaultsPath       = "/usr/bin/defaults"
	pmsetPath          = "/usr/bin/pmset"
	plutilPath         = "/usr/bin/plutil"

	installHistoryPath   = "/Library/Receipts/InstallHistory.plist"
	softwareUpdatePrefs  = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
	managedPrefsDir      = "/Library/Managed Preferences"
	plistReadLimit       = 1 << 20
	installHistoryLimit  = 16 << 20
	screensaverPrefsName = "com.apple.screensaver.plist"
)

// xprotectPlists are the Info.plist files of the XProtect data bundle: the
// classic location and the one macOS 15 and later update in place.
var xprotectPlists = []string{
	"/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
	"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
}

// plistXML returns a property list file as XML (binary files are converted
// with plutil).
func (c *Collector) plistXML(ctx context.Context, path string, limit int) ([]byte, error) {
	data, err := c.sys.read(path, limit)
	if err != nil {
		return nil, err
	}
	if !IsBinaryPlist(data) {
		return data, nil
	}
	out, err := c.sys.exec.Output(ctx, Cmd{Path: plutilPath, Args: []string{"-convert", "xml1", "-o", "-", "--", path}, MaxStdout: limit})
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (c *Collector) gatherAntivirus(ctx context.Context) ([]protocol.AntivirusProduct, error) {
	version := ""
	for _, p := range xprotectPlists {
		if data, err := c.plistXML(ctx, p, plistReadLimit); err == nil {
			version = HigherVersion(version, PlistString(data, "CFBundleShortVersionString"))
		}
	}

	var configData *bool
	for _, p := range []string{managedPrefsDir + "/com.apple.SoftwareUpdate.plist", softwareUpdatePrefs} {
		if data, err := c.plistXML(ctx, p, plistReadLimit); err == nil {
			if v, ok := PlistBool(data, "ConfigDataInstall"); ok {
				configData = &v
				break
			}
		}
	}

	var gatekeeper *bool
	// spctl exits 1 when assessments are disabled; the text decides.
	if res, err := c.sys.exec.Run(ctx, Cmd{Path: spctlPath, Args: []string{"--status"}}); err == nil {
		if on, ok := ParseGatekeeperStatus(res.Combined()); ok {
			gatekeeper = &on
		}
	}

	procs, err := c.sys.procs(ctx)
	if err != nil {
		c.log.Debug("process list not readable", "error", err)
	}
	known := DetectKnownAV(KnownAVDarwin, c.sys.exists, procs)

	products := MacAntivirus(version, configData, gatekeeper, known)
	if version == "" && gatekeeper == nil && len(known) == 0 {
		return nil, Unsupportedf("neither the XProtect bundle nor the Gatekeeper state is readable")
	}
	return products, nil
}

func (c *Collector) gatherFirewall(ctx context.Context) (*protocol.FirewallState, error) {
	if !c.sys.exists(socketFilterFWPath) {
		return nil, Unsupportedf("the Application Firewall tool (socketfilterfw) is missing")
	}
	out, err := c.sys.exec.Output(ctx, Cmd{Path: socketFilterFWPath, Args: []string{"--getglobalstate"}})
	if err != nil {
		return nil, err
	}
	return ParseSocketFilterFW(out)
}

func (c *Collector) gatherDiskEncryption(ctx context.Context) ([]protocol.DiskEncryption, error) {
	res, err := c.sys.exec.Run(ctx, Cmd{Path: fdesetupPath, Args: []string{"status"}})
	if err != nil {
		return nil, err
	}
	v, err := ParseFdesetupStatus(res.Combined())
	if err != nil {
		return nil, err
	}
	return []protocol.DiskEncryption{v}, nil
}

func (c *Collector) gatherLocalAdmins(ctx context.Context) ([]AdminAccount, error) {
	res, err := c.sys.exec.Run(ctx, Cmd{Path: dsclPath, Args: []string{".", "-read", "/Groups/admin", "GroupMembership"}})
	if err != nil {
		return nil, err
	}
	return ParseDsclGroupMembership(res.Combined())
}

// asUser returns the AsUser value for a command that must run as the console
// user: nil when the agent already is that user (development runs).
func (c *Collector) asUser(u *platform.User) *platform.User {
	if u.UID == strconv.Itoa(c.sys.euid()) {
		return nil
	}
	return u
}

func (c *Collector) gatherScreenLock(ctx context.Context) (*protocol.ScreenLock, error) {
	u, err := c.plat.ConsoleUser(ctx)
	if err != nil {
		if errors.Is(err, platform.ErrNoConsoleUser) {
			return nil, Unsupportedf("no user is logged in (the screen lock is a per-user setting)")
		}
		return nil, err
	}
	as := c.asUser(u)
	if as != nil && c.sys.euid() != 0 {
		return nil, Unsupportedf("reading another user's screen lock setting needs root")
	}

	// "Require password after sleep or screen saver begins" (sysadminctl
	// writes its answer to stderr).
	res, err := c.sys.exec.Run(ctx, Cmd{Path: sysadminctlPath, Args: []string{"-screenLock", "status"}, AsUser: as})
	if err != nil {
		return nil, err
	}
	delay, off, ok := ParseSysadminctlScreenLock(res.Combined())
	if !ok {
		return nil, Unsupportedf("sysadminctl did not report the screen lock setting")
	}

	// Screen saver idle time: a managed (MDM) preference wins over the user's own.
	saverIdle := 0
	managed := false
	var managedPaths []string
	if validUserDirName(u.Name) {
		managedPaths = append(managedPaths, managedPrefsDir+"/"+u.Name+"/"+screensaverPrefsName)
	}
	managedPaths = append(managedPaths, managedPrefsDir+"/"+screensaverPrefsName)
	for _, p := range managedPaths {
		if data, err := c.plistXML(ctx, p, plistReadLimit); err == nil {
			if n, ok := PlistInt(data, "idleTime"); ok && n >= 0 {
				saverIdle, managed = clampSeconds(int(n)), true
				break
			}
		}
	}
	if !managed {
		// Exit code 1 means the key is not set.
		if res, err := c.sys.exec.Run(ctx, Cmd{Path: defaultsPath, Args: []string{"-currentHost", "read", "com.apple.screensaver", "idleTime"}, AsUser: as}); err == nil && res.ExitCode == 0 {
			if n, err := strconv.Atoi(strings.TrimSpace(res.Stdout)); err == nil && n >= 0 {
				saverIdle = clampSeconds(n)
			}
		}
	}

	displaySleep := 0
	if out, err := c.sys.exec.Output(ctx, Cmd{Path: pmsetPath, Args: []string{"-g"}}); err == nil {
		displaySleep, _ = ParsePmsetDisplaySleep(out)
	}
	return MacScreenLock(off, delay, saverIdle, displaySleep), nil
}

// validUserDirName guards the use of an account name as a path element.
func validUserDirName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

func (c *Collector) gatherLastPatch(ctx context.Context) (time.Time, error) {
	if !c.sys.exists(installHistoryPath) {
		return time.Time{}, Unsupportedf("the install history (%s) does not exist", installHistoryPath)
	}
	data, err := c.plistXML(ctx, installHistoryPath, installHistoryLimit)
	if err != nil {
		return time.Time{}, err
	}
	return ParseInstallHistory(data)
}
