//go:build linux

package posture

import (
	"context"
	"errors"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Fixed file locations on Linux.
const (
	clamDBDir      = "/var/lib/clamav"
	ufwConfPath    = "/etc/ufw/ufw.conf"
	passwdPath     = "/etc/passwd"
	groupPath      = "/etc/group"
	dpkgLogPath    = "/var/log/dpkg.log"
	dpkgLogOldPath = "/var/log/dpkg.log.1"
	accountsLimit  = 4 << 20
	dpkgLogLimit   = 8 << 20
)

// cEnv makes tool output locale-independent.
var cEnv = []string{"LC_ALL=C", "LANG=C"}

func (c *Collector) gatherAntivirus(ctx context.Context) ([]protocol.AntivirusProduct, error) {
	procs, err := c.sys.procs(ctx)
	if err != nil {
		return nil, err
	}
	out := []protocol.AntivirusProduct{}

	clam := ClamAV{
		ClamdRunning:     HasProcess(procs, "clamd"),
		FreshclamRunning: HasProcess(procs, "freshclam"),
	}
	clam.Installed = clam.ClamdRunning || c.sys.look("clamd", "clamscan", "clamdscan", "freshclam") != "" || c.sys.exists(clamDBDir)
	if clam.Installed {
		// The first 512 bytes of the daily database carry its version and build time.
		for _, name := range []string{"daily.cld", "daily.cvd"} {
			header, err := c.sys.read(clamDBDir+"/"+name, 512)
			if err != nil {
				continue
			}
			if v, built, ok := ParseClamAVHeader(header); ok && (clam.Built.IsZero() || built.After(clam.Built)) {
				clam.Version, clam.Built = v, built
			}
		}
		out = append(out, ClamAVProduct(clam, c.sys.now()))
	}
	return append(out, DetectKnownAV(KnownAVLinux, c.sys.exists, procs)...), nil
}

// probe runs one firewall tool; nil when it is not installed.
func (c *Collector) probe(ctx context.Context, path string, args ...string) *Probe {
	if path == "" {
		return nil
	}
	res, err := c.sys.exec.Run(ctx, Cmd{Path: path, Args: args, Env: cEnv})
	return &Probe{Output: res.Combined(), ExitCode: res.ExitCode, Failed: err != nil}
}

func (c *Collector) gatherFirewall(ctx context.Context) (*protocol.FirewallState, error) {
	var p LinuxFirewallProbes
	if ufw := c.sys.look("ufw"); ufw != "" {
		p.UFW = c.probe(ctx, ufw, "status")
		if conf, err := c.sys.read(ufwConfPath, 64<<10); err == nil {
			p.UFWConf = string(conf)
		}
	}
	p.Firewalld = c.probe(ctx, c.sys.look("firewall-cmd"), "--state")
	if nft := c.sys.look("nft"); nft != "" {
		p.Nft = c.probe(ctx, nft, "list", "ruleset")
	} else {
		p.Iptables = c.probe(ctx, c.sys.look("iptables"), "-S", "INPUT")
	}
	return LinuxFirewall(p)
}

func (c *Collector) gatherDiskEncryption(ctx context.Context) ([]protocol.DiskEncryption, error) {
	lsblk := c.sys.look("lsblk")
	if lsblk == "" {
		return nil, Unsupportedf("lsblk is not installed")
	}
	// MOUNTPOINTS (util-linux 2.37+) lists every mount of a device; older
	// versions only know MOUNTPOINT.
	var lastErr error
	for _, column := range []string{"MOUNTPOINTS", "MOUNTPOINT"} {
		out, err := c.sys.exec.Output(ctx, Cmd{Path: lsblk, Args: []string{"-J", "-o", "NAME,TYPE,FSTYPE," + column}, Env: cEnv})
		if err != nil {
			lastErr = err
			continue
		}
		return ParseLsblk([]byte(out))
	}
	return nil, lastErr
}

func (c *Collector) gatherLocalAdmins(_ context.Context) ([]AdminAccount, error) {
	passwd, err := c.sys.read(passwdPath, accountsLimit)
	if err != nil {
		return nil, err
	}
	group, err := c.sys.read(groupPath, accountsLimit)
	if err != nil {
		return nil, err
	}
	return ParseLinuxAdmins(string(passwd), string(group)), nil
}

func (c *Collector) gatherScreenLock(ctx context.Context) (*protocol.ScreenLock, error) {
	gsettings := c.sys.look("gsettings")
	if gsettings == "" {
		return nil, Unsupportedf("no GNOME desktop (gsettings) is installed")
	}
	u, err := c.plat.ConsoleUser(ctx)
	if err != nil {
		if errors.Is(err, platform.ErrNoConsoleUser) {
			return nil, Unsupportedf("no user is logged in at the console (the screen lock is a per-user setting)")
		}
		return nil, err
	}
	// The platform runs the command in the user's session with the user's
	// D-Bus session address, which gsettings (dconf) needs.
	get := func(schema, key string) (string, error) {
		return c.sys.exec.Output(ctx, Cmd{Path: gsettings, Args: []string{"get", schema, key}, Env: cEnv, AsUser: u, Timeout: 15 * time.Second})
	}
	idleOut, err := get("org.gnome.desktop.session", "idle-delay")
	if err != nil {
		return nil, Unsupportedf("the GNOME settings of the console user are not readable (%v)", err)
	}
	lockOut, err := get("org.gnome.desktop.screensaver", "lock-enabled")
	if err != nil {
		return nil, Unsupportedf("the GNOME settings of the console user are not readable (%v)", err)
	}
	idle, ok1 := ParseGsettingsUint(idleOut)
	lockEnabled, ok2 := ParseGsettingsBool(lockOut)
	if !ok1 || !ok2 {
		return nil, Unsupportedf("unrecognised gsettings output")
	}
	lockDelay := 0
	if out, err := get("org.gnome.desktop.screensaver", "lock-delay"); err == nil {
		lockDelay, _ = ParseGsettingsUint(out)
	}
	return GnomeScreenLock(idle, lockEnabled, lockDelay), nil
}

func (c *Collector) gatherLastPatch(ctx context.Context) (time.Time, error) {
	supported := false
	for _, path := range []string{dpkgLogPath, dpkgLogOldPath} {
		if !c.sys.exists(path) {
			continue
		}
		supported = true
		data, err := c.sys.read(path, dpkgLogLimit)
		if err != nil {
			continue
		}
		if t, ok := ParseDpkgLog(string(data), time.Local); ok {
			return t, nil
		}
	}
	if rpm := c.sys.look("rpm"); rpm != "" {
		// Install times as Unix seconds: independent of the locale and of
		// the date format `rpm -qa --last` prints.
		out, err := c.sys.exec.Output(ctx, Cmd{Path: rpm, Args: []string{"-qa", "--queryformat", `%{INSTALLTIME}\n`}, Env: cEnv, Timeout: 60 * time.Second})
		if err != nil {
			return time.Time{}, err
		}
		t, _ := ParseRpmInstallTimes(out)
		return t, nil
	}
	if !supported {
		return time.Time{}, Unsupportedf("neither a dpkg log nor rpm is available")
	}
	return time.Time{}, nil
}
