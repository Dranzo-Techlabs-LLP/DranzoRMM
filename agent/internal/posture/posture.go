// Package posture collects the "posture" report (PROTOCOL.md section 7.3):
// antivirus, firewall, disk encryption, local administrators, screen lock,
// last patch date, pending reboot and listening ports.
//
// Everything here is read-only detection. The collector never changes a
// setting and never touches a security product; it only asks the operating
// system (and well-known files) what the current state is.
//
// Layout: every sub-collector is a pure parser in an untagged parse_*.go file
// (fixture-tested for all three systems) plus a thin gatherer in
// gather_windows.go / gather_darwin.go / gather_linux.go that runs the fixed
// helper command or reads the file. A sub-collector that cannot run on this
// OS, edition or in the current state returns an *UnsupportedError; Collect
// then leaves the field null and lists its name in "unsupported". Nothing is
// ever guessed.
package posture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/logging"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ReporterName is the name the posture reporter is registered under.
const ReporterName = "posture"

// Names of the sub-sections as they appear in Posture.Unsupported (the JSON
// field names of PROTOCOL.md section 7.3).
const (
	SectionAntivirus      = "antivirus"
	SectionFirewall       = "firewall"
	SectionDiskEncryption = "diskEncryption"
	SectionLocalAdmins    = "localAdmins"
	SectionScreenLock     = "screenLock"
	SectionLastPatchDate  = "lastPatchDate"
	SectionPendingReboot  = "pendingReboot"
	SectionListeningPorts = "listeningPorts"
)

// Limits.
const (
	// MaxListeningPorts caps Posture.ListeningPorts.
	MaxListeningPorts = 500
	// MaxLocalAdmins caps Posture.LocalAdmins.
	MaxLocalAdmins = 500
	// MaxVolumes caps Posture.DiskEncryption.
	MaxVolumes = 128
	// MaxAntivirusProducts caps Posture.Antivirus.
	MaxAntivirusProducts = 32
	// sectionTimeout bounds one sub-collector.
	sectionTimeout = 2 * time.Minute
)

// UnsupportedError marks a sub-collector (or policy check) that cannot run on
// this OS, edition or in the current state. Its text always starts with
// "not supported on this OS: ".
type UnsupportedError struct{ Reason string }

// UnsupportedPrefix starts every "the OS cannot do this" message.
const UnsupportedPrefix = "not supported on this OS: "

func (e *UnsupportedError) Error() string { return UnsupportedPrefix + e.Reason }

// Is makes errors.Is(err, platform.ErrUnsupported) true.
func (e *UnsupportedError) Is(target error) bool { return target == platform.ErrUnsupported }

// Unsupportedf builds an *UnsupportedError.
func Unsupportedf(format string, args ...any) error {
	return &UnsupportedError{Reason: fmt.Sprintf(format, args...)}
}

// sys is the collector's access to the machine. Tests replace the fields.
type sys struct {
	exec Exec
	// look returns the absolute path of the first of names found in the fixed
	// system directories ("" if none is installed).
	look func(names ...string) string
	// read returns at most limit bytes of a file.
	read func(path string, limit int) ([]byte, error)
	// exists reports whether path exists.
	exists func(path string) bool
	// procs lists the names of the running processes.
	procs func(ctx context.Context) ([]string, error)
	now   func() time.Time
	euid  func() int
}

// Collector builds posture reports. Its sub-collectors are also used one by
// one by the policy checks.
type Collector struct {
	plat platform.Platform
	log  *slog.Logger
	sys  sys
}

// New returns a collector that uses p for running helper commands.
func New(p platform.Platform, log *slog.Logger) *Collector {
	if log == nil {
		log = logging.Discard()
	}
	return &Collector{
		plat: p,
		log:  log,
		sys: sys{
			exec:   Exec{Platform: p},
			look:   LookTool,
			read:   readLimited,
			exists: pathExists,
			procs:  processNames,
			now:    time.Now,
			euid:   os.Geteuid,
		},
	}
}

func (c *Collector) section(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, sectionTimeout)
}

// Antivirus lists the detected antivirus products (empty when none is found).
func (c *Collector) Antivirus(ctx context.Context) ([]protocol.AntivirusProduct, error) {
	ctx, cancel := c.section(ctx)
	defer cancel()
	av, err := c.gatherAntivirus(ctx)
	if err != nil {
		return nil, err
	}
	if len(av) > MaxAntivirusProducts {
		av = av[:MaxAntivirusProducts]
	}
	if av == nil {
		av = []protocol.AntivirusProduct{}
	}
	return av, nil
}

// Firewall returns the host firewall state.
func (c *Collector) Firewall(ctx context.Context) (*protocol.FirewallState, error) {
	ctx, cancel := c.section(ctx)
	defer cancel()
	return c.gatherFirewall(ctx)
}

// DiskEncryption returns the encryption state of the fixed volumes.
func (c *Collector) DiskEncryption(ctx context.Context) ([]protocol.DiskEncryption, error) {
	ctx, cancel := c.section(ctx)
	defer cancel()
	vols, err := c.gatherDiskEncryption(ctx)
	if err != nil {
		return nil, err
	}
	if len(vols) > MaxVolumes {
		vols = vols[:MaxVolumes]
	}
	if vols == nil {
		vols = []protocol.DiskEncryption{}
	}
	return vols, nil
}

// LocalAdminAccounts returns the members of the local administrators group
// (Windows: S-1-5-32-544; macOS: admin; Linux: sudo, wheel, admin and uid 0)
// with the details the localadmins policy check needs.
func (c *Collector) LocalAdminAccounts(ctx context.Context) ([]AdminAccount, error) {
	ctx, cancel := c.section(ctx)
	defer cancel()
	admins, err := c.gatherLocalAdmins(ctx)
	if err != nil {
		return nil, err
	}
	if len(admins) > MaxLocalAdmins {
		admins = admins[:MaxLocalAdmins]
	}
	return admins, nil
}

// LocalAdmins returns the sorted names of the local administrators.
func (c *Collector) LocalAdmins(ctx context.Context) ([]string, error) {
	admins, err := c.LocalAdminAccounts(ctx)
	if err != nil {
		return nil, err
	}
	return AdminNames(admins), nil
}

// ScreenLock returns the automatic screen lock configuration.
func (c *Collector) ScreenLock(ctx context.Context) (*protocol.ScreenLock, error) {
	ctx, cancel := c.section(ctx)
	defer cancel()
	return c.gatherScreenLock(ctx)
}

// LastPatchDate returns when an operating system update was last installed.
func (c *Collector) LastPatchDate(ctx context.Context) (*time.Time, error) {
	ctx, cancel := c.section(ctx)
	defer cancel()
	t, err := c.gatherLastPatch(ctx)
	if err != nil {
		return nil, err
	}
	if t.IsZero() {
		return nil, Unsupportedf("no installed update was found in the update history")
	}
	u := t.UTC().Truncate(time.Second)
	return &u, nil
}

// ListeningPorts returns the listening TCP sockets and bound UDP sockets
// (at most MaxListeningPorts).
func (c *Collector) ListeningPorts(ctx context.Context) ([]protocol.ListeningPort, error) {
	ctx, cancel := c.section(ctx)
	defer cancel()
	return gatherListeningPorts(ctx)
}

// Collect runs every sub-collector and builds the report. It never fails:
// what cannot be collected is null and listed in Unsupported.
func (c *Collector) Collect(ctx context.Context) *protocol.Posture {
	p := &protocol.Posture{CollectedAt: c.sys.now().UTC().Truncate(time.Second), Unsupported: []string{}}
	miss := func(section string, err error) {
		p.Unsupported = append(p.Unsupported, section)
		var ue *UnsupportedError
		if errors.As(err, &ue) || errors.Is(err, platform.ErrUnsupported) {
			c.log.Debug("posture section not supported", slog.String("section", section), slog.String("reason", err.Error()))
			return
		}
		c.log.Warn("posture section failed", slog.String("section", section), slog.Any("error", err))
	}

	if av, err := c.Antivirus(ctx); err != nil {
		miss(SectionAntivirus, err)
	} else {
		p.Antivirus = av
	}
	if fw, err := c.Firewall(ctx); err != nil {
		miss(SectionFirewall, err)
	} else {
		p.Firewall = fw
	}
	if vols, err := c.DiskEncryption(ctx); err != nil {
		miss(SectionDiskEncryption, err)
	} else {
		p.DiskEncryption = vols
	}
	if admins, err := c.LocalAdmins(ctx); err != nil {
		miss(SectionLocalAdmins, err)
	} else {
		p.LocalAdmins = admins
	}
	if sl, err := c.ScreenLock(ctx); err != nil {
		miss(SectionScreenLock, err)
	} else {
		p.ScreenLock = sl
	}
	if t, err := c.LastPatchDate(ctx); err != nil {
		miss(SectionLastPatchDate, err)
	} else {
		p.LastPatchDate = t
	}
	if reboot, err := c.plat.PendingReboot(ctx); err != nil {
		miss(SectionPendingReboot, err)
	} else {
		p.PendingReboot = reboot
	}
	if ports, err := c.ListeningPorts(ctx); err != nil {
		miss(SectionListeningPorts, err)
	} else {
		p.ListeningPorts = ports
	}
	return p
}

// Reporter adapts the collector to the agent core's periodic reporter
// signature: it returns the message type and payload of one posture report.
func Reporter(c *Collector) func(ctx context.Context) (msgType string, payload any, err error) {
	return func(ctx context.Context) (string, any, error) {
		return protocol.TypePosture, c.Collect(ctx), nil
	}
}
