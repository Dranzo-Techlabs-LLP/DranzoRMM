package patch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// Timeouts of the update tools.
const (
	refreshTimeout = 10 * time.Minute
	scanTimeout    = 15 * time.Minute
	// rescanTimeout bounds the query after an installation that decides the
	// per-update results.
	rescanTimeout = 5 * time.Minute
	// outputTail is how much of an installer's output is kept for inspection.
	outputTail = 64 << 10
)

// errAbsent reports that a source's tool is not installed on this machine.
var errAbsent = errors.New("not installed")

// ScanResult is what one source reports.
type ScanResult struct {
	Pending        []protocol.PendingPatch
	RebootRequired bool
	LastInstallAt  *time.Time
	// Warning is a non-fatal problem (for example a failed index refresh).
	Warning string
}

// InstallRequest selects what a source installs.
type InstallRequest struct {
	// All installs everything pending; otherwise Names (native names, already
	// decoded from the update ids) are installed.
	All   bool
	Names []string
	// Out and Err receive the tools' output (the job output).
	Out io.Writer
	Err io.Writer
}

// InstallOutcome is what one source did.
type InstallOutcome struct {
	Items          []protocol.PatchInstallItem
	RebootRequired bool
	// Restart, if set, is how this source wants the machine restarted to
	// finish its updates (macOS: softwareupdate applies staged system
	// updates only through its own restart).
	Restart func(ctx context.Context) error
}

// Provider is one update source.
type Provider interface {
	// Source is the protocol name of the source.
	Source() string
	// Optional sources are third-party tools: when their tool is not
	// installed the source is skipped silently instead of being reported
	// as unsupported.
	Optional() bool
	// Check returns errAbsent (wrapped) when the tool is not installed, or
	// another error when the source cannot be used right now.
	Check(ctx context.Context) error
	// Scan lists the pending updates. refresh first updates the source's
	// index from the network.
	Scan(ctx context.Context, refresh bool) (ScanResult, error)
	// Install installs updates and reports one item per update.
	Install(ctx context.Context, req InstallRequest) (InstallOutcome, error)
}

func item(source, name string, ok bool, errText string) protocol.PatchInstallItem {
	id, valid := EncodeID(source, name)
	if !valid {
		id = source + ":invalid"
	}
	it := protocol.PatchInstallItem{ID: id, OK: ok}
	if !ok {
		it.Error = software.Clean(errText, 300)
		if it.Error == "" {
			it.Error = "installation failed"
		}
	}
	return it
}

func failAll(source string, names []string, errText string) []protocol.PatchInstallItem {
	items := make([]protocol.PatchInstallItem, 0, len(names))
	for _, n := range names {
		items = append(items, item(source, n, false, errText))
	}
	return items
}

func pendingNames(pending []protocol.PendingPatch) map[string]bool {
	set := make(map[string]bool, len(pending))
	for _, p := range pending {
		if _, name, ok := DecodeID(p.ID); ok {
			set[name] = true
		}
	}
	return set
}

// splitValid separates names the tool may be given from invalid ones.
func splitValid(source string, names []string, valid func(string) bool) (good []string, bad []protocol.PatchInstallItem) {
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if valid(n) {
			good = append(good, n)
		} else {
			bad = append(bad, item(source, n, false, "not a valid update name for this source"))
		}
	}
	return good, bad
}

// selectPending decides what a batch source installs. With req.All it is
// everything pending; otherwise the requested names that are valid for the
// tool AND currently pending: an update that is not pending (already
// installed, never available, a typo) gets its own error instead of being
// handed to the tool, which would otherwise treat it as a plain install.
func selectPending(ctx context.Context, p Provider, req InstallRequest, refresh bool, valid func(string) bool) (good []string, bad []protocol.PatchInstallItem, err error) {
	scan, err := p.Scan(ctx, refresh)
	if err != nil {
		return nil, nil, err
	}
	pending := pendingNames(scan.Pending)
	if req.All {
		for name := range pending {
			good = append(good, name)
		}
		sort.Strings(good)
		good, bad = splitValid(p.Source(), good, valid)
		return good, bad, nil
	}
	candidates, bad := splitValid(p.Source(), req.Names, valid)
	for _, n := range candidates {
		if pending[n] {
			good = append(good, n)
		} else {
			bad = append(bad, item(p.Source(), n, false, "the update is not pending on this device"))
		}
	}
	return good, bad, nil
}

// runStream runs a tool with its output streamed to the job.
func runStream(ctx context.Context, plat platform.Platform, req InstallRequest, cmd platform.Command) (code int, tail string, err error) {
	if req.Out != nil {
		fmt.Fprintf(req.Out, "> %s %s\n", toolName(cmd.Path), strings.Join(cmd.Args, " "))
	}
	t := software.NewTail(req.Out, outputTail)
	e := software.NewTail(req.Err, outputTail)
	cmd.Stdout, cmd.Stderr = t, e
	cmd.Env = software.WithCLocale(cmd.Env)
	code, err = plat.Run(ctx, cmd)
	return code, t.String() + "\n" + e.String(), err
}

func toolName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(path), ".exe")
}

// rescanItems decides the per-update result after a batch installation: an
// update that is no longer pending was installed.
func rescanItems(ctx context.Context, p Provider, names []string, exit int, tool string) []protocol.PatchInstallItem {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rescanTimeout)
	defer cancel()
	after, err := p.Scan(rctx, false)
	items := make([]protocol.PatchInstallItem, 0, len(names))
	if err != nil {
		// No way to tell the updates apart: the exit code decides for all.
		for _, n := range names {
			items = append(items, item(p.Source(), n, exit == 0, fmt.Sprintf("%s exited with code %d", tool, exit)))
		}
		return items
	}
	still := pendingNames(after.Pending)
	for _, n := range names {
		switch {
		case !still[n]:
			items = append(items, item(p.Source(), n, true, ""))
		case exit != 0:
			items = append(items, item(p.Source(), n, false, fmt.Sprintf("%s exited with code %d", tool, exit)))
		default:
			items = append(items, item(p.Source(), n, false, "the update is still pending after the installation"))
		}
	}
	return items
}

// ---- apt ----

// AptProvider handles Debian / Ubuntu system updates.
type AptProvider struct {
	Plat   platform.Platform
	Lookup software.Lookup
	// HistoryLog is /var/log/apt/history.log (tests point it elsewhere).
	HistoryLog string
}

var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

// Source implements Provider.
func (p *AptProvider) Source() string { return SourceApt }

// Optional implements Provider: a Linux machine has apt or dnf, not both.
func (p *AptProvider) Optional() bool { return true }

// Check implements Provider.
func (p *AptProvider) Check(context.Context) error {
	if p.Lookup("apt-get") == "" {
		return fmt.Errorf("apt-get: %w", errAbsent)
	}
	return nil
}

func aptPatch(u AptUpgrade) (protocol.PendingPatch, bool) {
	id, ok := EncodeID(SourceApt, u.Name)
	if !ok {
		return protocol.PendingPatch{}, false
	}
	category := CategoryUpdate
	if u.Security {
		category = CategorySecurity
	}
	return protocol.PendingPatch{
		ID:             id,
		Title:          software.Clean(u.Name+" "+u.NewVersion, 256),
		Category:       category,
		Severity:       SeverityUnspecified,
		Source:         SourceApt,
		CurrentVersion: software.Clean(u.CurrentVersion, 128),
		NewVersion:     software.Clean(u.NewVersion, 128),
	}, true
}

// readTail returns at most the last limit bytes of a file.
func readTail(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil && fi.Size() > limit {
		if _, err := f.Seek(-limit, io.SeekEnd); err != nil {
			return "", err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	return string(data), err
}

// Scan implements Provider.
func (p *AptProvider) Scan(ctx context.Context, refresh bool) (ScanResult, error) {
	var res ScanResult
	aptGet := p.Lookup("apt-get")
	if refresh {
		out, err := software.Output(ctx, p.Plat, refreshTimeout, platform.Command{Path: aptGet, Args: []string{"-o", "DPkg::Lock::Timeout=60", "update"}, Env: aptEnv})
		switch {
		case err != nil:
			res.Warning = fmt.Sprintf("apt-get update: %v", err)
		case out.ExitCode != 0:
			res.Warning = fmt.Sprintf("apt-get update exited with code %d", out.ExitCode)
		}
	}
	var ups []AptUpgrade
	listed := false
	if apt := p.Lookup("apt"); apt != "" {
		out, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{Path: apt, Args: []string{"list", "--upgradable"}, Env: aptEnv})
		if err == nil && out.ExitCode == 0 {
			ups, listed = ParseAptUpgradable(out.Stdout), true
		}
	}
	if !listed {
		out, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{Path: aptGet, Args: []string{"-s", "-o", "Debug::NoLocking=1", "dist-upgrade"}, Env: aptEnv})
		if err != nil {
			return res, fmt.Errorf("apt-get -s dist-upgrade: %w", err)
		}
		if out.ExitCode != 0 {
			return res, fmt.Errorf("apt-get -s dist-upgrade exited with code %d: %s", out.ExitCode, software.Clean(out.Stderr, 200))
		}
		ups = ParseAptSimulate(out.Stdout)
	}
	for _, u := range ups {
		if patch, ok := aptPatch(u); ok {
			res.Pending = append(res.Pending, patch)
		}
	}
	if p.HistoryLog != "" {
		if content, err := readTail(p.HistoryLog, 256<<10); err == nil {
			if t, ok := ParseAptHistoryLast(content, time.Local); ok {
				t = t.UTC()
				res.LastInstallAt = &t
			}
		}
	}
	return res, nil
}

// Install implements Provider.
func (p *AptProvider) Install(ctx context.Context, req InstallRequest) (InstallOutcome, error) {
	good, bad, err := selectPending(ctx, p, req, true, software.ValidAptName)
	if err != nil {
		return InstallOutcome{}, err
	}
	out := InstallOutcome{Items: bad}
	if len(good) == 0 {
		return out, nil
	}
	args := []string{
		"-y",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "DPkg::Lock::Timeout=120",
		"install", "--only-upgrade", "--",
	}
	args = append(args, good...)
	code, _, err := runStream(ctx, p.Plat, req, platform.Command{Path: p.Lookup("apt-get"), Args: args, Env: aptEnv})
	if err != nil {
		return out, err
	}
	out.Items = append(out.Items, rescanItems(ctx, p, good, code, "apt-get")...)
	return out, nil
}

// ---- dnf ----

// DnfProvider handles RHEL-family system updates.
type DnfProvider struct {
	Plat   platform.Platform
	Lookup software.Lookup
}

// Source implements Provider.
func (p *DnfProvider) Source() string { return SourceDnf }

// Optional implements Provider.
func (p *DnfProvider) Optional() bool { return true }

// Check implements Provider.
func (p *DnfProvider) Check(context.Context) error {
	if p.Lookup("dnf") == "" {
		return fmt.Errorf("dnf: %w", errAbsent)
	}
	return nil
}

// Scan implements Provider.
func (p *DnfProvider) Scan(ctx context.Context, refresh bool) (ScanResult, error) {
	var res ScanResult
	dnf := p.Lookup("dnf")
	args := []string{"-q", "check-update"}
	if refresh {
		args = append(args, "--refresh")
	}
	out, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{Path: dnf, Args: args})
	if err != nil {
		return res, fmt.Errorf("dnf check-update: %w", err)
	}
	// Exit code 100: updates are available; 0: none; anything else: error.
	if out.ExitCode != 0 && out.ExitCode != 100 {
		return res, fmt.Errorf("dnf check-update exited with code %d: %s", out.ExitCode, software.Clean(out.Stderr, 200))
	}
	ups := ParseDnfCheckUpdate(out.Stdout)

	// Security classification (best effort: needs updateinfo metadata).
	severity := map[string]string{}
	if len(ups) > 0 {
		if info, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{Path: dnf, Args: []string{"-q", "updateinfo", "list", "--security"}}); err == nil && info.ExitCode == 0 {
			severity = ParseDnfUpdateinfo(info.Stdout)
		}
	}
	current := map[string]string{}
	rpm := p.Lookup("rpm")
	if rpm != "" && len(ups) > 0 {
		args := []string{"-q", "--qf", `%{NAME}.%{ARCH}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n`, "--"}
		for _, u := range ups {
			if software.ValidRpmName(u.NameArch()) {
				args = append(args, u.NameArch())
			}
		}
		if q, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{Path: rpm, Args: args}); err == nil {
			for _, l := range software.Lines(q.Stdout) {
				f := strings.Split(l, "\t")
				if len(f) != 4 {
					continue
				}
				v := software.RpmVersion(f[1], f[2], f[3])
				// Several installed versions (kernels): the newest is "current".
				if old, ok := current[f[0]]; !ok || software.CompareVersions(v, old) > 0 {
					current[f[0]] = v
				}
			}
		}
	}
	for _, u := range ups {
		id, ok := EncodeID(SourceDnf, u.NameArch())
		if !ok {
			continue
		}
		patch := protocol.PendingPatch{
			ID:             id,
			Title:          software.Clean(u.Name+" "+u.Version, 256),
			Category:       CategoryUpdate,
			Severity:       SeverityUnspecified,
			Source:         SourceDnf,
			CurrentVersion: software.Clean(current[u.NameArch()], 128),
			NewVersion:     software.Clean(u.Version, 128),
		}
		if sev, sec := severity[u.NameArch()]; sec {
			patch.Category = CategorySecurity
			patch.Severity = sev
		}
		res.Pending = append(res.Pending, patch)
	}
	if rpm != "" {
		if q, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{Path: rpm, Args: []string{"-qa", "--qf", `%{INSTALLTIME}\n`}}); err == nil && q.ExitCode == 0 {
			var newest int64
			for _, l := range software.Lines(q.Stdout) {
				if n, err := strconv.ParseInt(strings.TrimSpace(l), 10, 64); err == nil && n > newest {
					newest = n
				}
			}
			if newest > 0 {
				t := time.Unix(newest, 0).UTC()
				res.LastInstallAt = &t
			}
		}
	}
	return res, nil
}

// Install implements Provider.
func (p *DnfProvider) Install(ctx context.Context, req InstallRequest) (InstallOutcome, error) {
	good, bad, err := selectPending(ctx, p, req, false, software.ValidRpmName)
	if err != nil {
		return InstallOutcome{}, err
	}
	out := InstallOutcome{Items: bad}
	if len(good) == 0 {
		return out, nil
	}
	args := append([]string{"-y", "upgrade", "--"}, good...)
	code, _, err := runStream(ctx, p.Plat, req, platform.Command{Path: p.Lookup("dnf"), Args: args})
	if err != nil {
		return out, err
	}
	out.Items = append(out.Items, rescanItems(ctx, p, good, code, "dnf")...)
	return out, nil
}

// ---- macOS softwareupdate ----

// SoftwareUpdateProvider handles Apple's system updates.
type SoftwareUpdateProvider struct {
	Plat   platform.Platform
	Lookup software.Lookup
}

func validLabel(s string) bool {
	return s != "" && len(s) <= 200 && !strings.HasPrefix(s, "-") && strings.IndexFunc(s, unicode.IsControl) < 0
}

// Source implements Provider.
func (p *SoftwareUpdateProvider) Source() string { return SourceSoftwareUpdate }

// Optional implements Provider.
func (p *SoftwareUpdateProvider) Optional() bool { return false }

// Check implements Provider.
func (p *SoftwareUpdateProvider) Check(context.Context) error {
	if p.Lookup("softwareupdate") == "" {
		return fmt.Errorf("softwareupdate: %w", errAbsent)
	}
	return nil
}

func (p *SoftwareUpdateProvider) list(ctx context.Context) ([]SoftwareUpdateItem, error) {
	out, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{Path: p.Lookup("softwareupdate"), Args: []string{"--list"}})
	if err != nil {
		return nil, fmt.Errorf("softwareupdate --list: %w", err)
	}
	if out.ExitCode != 0 {
		return nil, fmt.Errorf("softwareupdate --list exited with code %d: %s", out.ExitCode, software.Clean(out.Stderr, 200))
	}
	return ParseSoftwareUpdateList(out.Stdout), nil
}

// Scan implements Provider. softwareupdate always asks Apple's servers, so
// refresh makes no difference.
func (p *SoftwareUpdateProvider) Scan(ctx context.Context, _ bool) (ScanResult, error) {
	var res ScanResult
	items, err := p.list(ctx)
	if err != nil {
		return res, err
	}
	for _, it := range items {
		if !validLabel(it.Label) {
			continue
		}
		id, ok := EncodeID(SourceSoftwareUpdate, it.Label)
		if !ok {
			continue
		}
		restart := it.Restart
		patch := protocol.PendingPatch{
			ID:             id,
			Title:          software.Clean(it.Title, 256),
			Category:       softwareUpdateCategory(it.Title),
			Severity:       SeverityUnspecified,
			Source:         SourceSoftwareUpdate,
			NewVersion:     software.Clean(it.Version, 128),
			RequiresReboot: &restart,
		}
		if it.SizeBytes > 0 {
			size := it.SizeBytes
			patch.SizeBytes = &size
		}
		res.Pending = append(res.Pending, patch)
	}
	return res, nil
}

// Install implements Provider. Each label is installed on its own so that
// each gets its own result. Updates that need a restart are downloaded and
// prepared without "--restart" (the job result must be sent before the
// machine restarts); the returned Restart function finishes them with
// "softwareupdate --install <labels> --restart" when the reboot policy says
// so.
func (p *SoftwareUpdateProvider) Install(ctx context.Context, req InstallRequest) (InstallOutcome, error) {
	var out InstallOutcome
	tool := p.Lookup("softwareupdate")
	restartOf := map[string]bool{}
	listed, listErr := p.list(ctx)
	for _, it := range listed {
		restartOf[it.Label] = it.Restart
	}
	names := req.Names
	if req.All {
		if listErr != nil {
			return out, listErr
		}
		names = names[:0:0]
		for _, it := range listed {
			names = append(names, it.Label)
		}
	}
	good, bad := splitValid(SourceSoftwareUpdate, names, validLabel)
	out.Items = bad
	var restartLabels []string
	for _, label := range good {
		if err := ctx.Err(); err != nil {
			out.Items = append(out.Items, item(SourceSoftwareUpdate, label, false, "not attempted: "+err.Error()))
			continue
		}
		if listErr == nil {
			if _, pending := restartOf[label]; !pending {
				out.Items = append(out.Items, item(SourceSoftwareUpdate, label, false, "the update is not pending on this device"))
				continue
			}
		}
		code, tail, err := runStream(ctx, p.Plat, req, platform.Command{Path: tool, Args: []string{"--install", label}})
		if err != nil {
			out.Items = append(out.Items, item(SourceSoftwareUpdate, label, false, err.Error()))
			continue
		}
		if reason := SoftwareUpdateFailure(tail); reason != "" {
			out.Items = append(out.Items, item(SourceSoftwareUpdate, label, false, reason))
			continue
		}
		if code != 0 {
			out.Items = append(out.Items, item(SourceSoftwareUpdate, label, false, fmt.Sprintf("softwareupdate exited with code %d", code)))
			continue
		}
		out.Items = append(out.Items, item(SourceSoftwareUpdate, label, true, ""))
		if restartOf[label] || strings.Contains(strings.ToLower(tail), "restart") {
			out.RebootRequired = true
			restartLabels = append(restartLabels, label)
		}
	}
	if len(restartLabels) > 0 {
		out.Restart = func(ctx context.Context) error {
			args := append([]string{"--install"}, restartLabels...)
			args = append(args, "--restart")
			res, err := software.Output(ctx, p.Plat, 0, platform.Command{Path: tool, Args: args})
			if err != nil {
				return err
			}
			if reason := SoftwareUpdateFailure(res.Stdout + "\n" + res.Stderr); reason != "" {
				return errors.New(reason)
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("softwareupdate --restart exited with code %d", res.ExitCode)
			}
			return nil
		}
	}
	return out, nil
}

// ---- Homebrew ----

// BrewProvider handles third-party updates on macOS. Every command runs as
// the console user, never as root.
type BrewProvider struct {
	Brew *software.Brew
}

// Source implements Provider.
func (p *BrewProvider) Source() string { return SourceBrew }

// Optional implements Provider.
func (p *BrewProvider) Optional() bool { return true }

// Check implements Provider.
func (p *BrewProvider) Check(ctx context.Context) error {
	if !p.Brew.Installed() {
		return fmt.Errorf("brew: %w", errAbsent)
	}
	// Fails with "no logged-in user" when brew would have to run as root.
	_, err := p.Brew.Command(ctx, false, "--version")
	return err
}

// Scan implements Provider.
func (p *BrewProvider) Scan(ctx context.Context, refresh bool) (ScanResult, error) {
	var res ScanResult
	if refresh {
		cmd, err := p.Brew.Command(ctx, true, "update", "--quiet")
		if err != nil {
			return res, err
		}
		if out, err := software.Output(ctx, p.Brew.Plat, refreshTimeout, cmd); err != nil || out.ExitCode != 0 {
			res.Warning = "brew update failed; the list of outdated packages may be stale"
		}
	}
	cmd, err := p.Brew.Command(ctx, false, "outdated", "--json=v2")
	if err != nil {
		return res, err
	}
	out, err := software.Output(ctx, p.Brew.Plat, scanTimeout, cmd)
	if err != nil {
		return res, fmt.Errorf("brew outdated: %w", err)
	}
	if out.ExitCode != 0 {
		return res, fmt.Errorf("brew outdated exited with code %d: %s", out.ExitCode, software.Clean(out.Stderr, 200))
	}
	outdated, err := ParseBrewOutdated(out.Stdout)
	if err != nil {
		return res, fmt.Errorf("brew outdated: %w", err)
	}
	for _, o := range outdated {
		if o.Pinned || !software.ValidBrewName(o.Name) {
			continue // a pinned formula is deliberately held back
		}
		id, ok := EncodeID(SourceBrew, o.Name)
		if !ok {
			continue
		}
		res.Pending = append(res.Pending, protocol.PendingPatch{
			ID:             id,
			Title:          software.Clean(o.Name+" "+o.Current, 256),
			Category:       CategoryApplication,
			Severity:       SeverityUnspecified,
			Source:         SourceBrew,
			CurrentVersion: software.Clean(o.Installed, 128),
			NewVersion:     software.Clean(o.Current, 128),
		})
	}
	return res, nil
}

// Install implements Provider.
func (p *BrewProvider) Install(ctx context.Context, req InstallRequest) (InstallOutcome, error) {
	good, bad, err := selectPending(ctx, p, req, false, software.ValidBrewName)
	if err != nil {
		return InstallOutcome{}, err
	}
	out := InstallOutcome{Items: bad}
	if len(good) == 0 {
		return out, nil
	}
	cmd, err := p.Brew.Command(ctx, true, append([]string{"upgrade", "--"}, good...)...)
	if err != nil {
		return out, err
	}
	code, _, err := runStream(ctx, p.Brew.Plat, req, cmd)
	if err != nil {
		return out, err
	}
	out.Items = append(out.Items, rescanItems(ctx, p, good, code, "brew")...)
	return out, nil
}

// ---- winget ----

// WingetProvider handles third-party updates on Windows.
type WingetProvider struct {
	Plat   platform.Platform
	Lookup software.Lookup
}

// Source implements Provider.
func (p *WingetProvider) Source() string { return SourceWinget }

// Optional implements Provider: winget is part of Windows, so a machine
// where the service cannot use it reports "winget" as unsupported.
func (p *WingetProvider) Optional() bool { return false }

// Check implements Provider.
func (p *WingetProvider) Check(context.Context) error {
	if p.Lookup("winget") == "" {
		return fmt.Errorf("winget is not available to the agent service: %w", errAbsent)
	}
	return nil
}

// Scan implements Provider.
func (p *WingetProvider) Scan(ctx context.Context, _ bool) (ScanResult, error) {
	var res ScanResult
	out, err := software.Output(ctx, p.Plat, scanTimeout, platform.Command{
		Path: p.Lookup("winget"),
		Args: []string{"upgrade", "--accept-source-agreements", "--disable-interactivity"},
	})
	if err != nil {
		return res, fmt.Errorf("winget upgrade: %w", err)
	}
	rows := software.ParseWingetTable(out.Stdout)
	if out.ExitCode != 0 && len(rows) == 0 {
		return res, fmt.Errorf("winget upgrade exited with code %d", out.ExitCode)
	}
	for _, r := range rows {
		if r.Available == "" || !software.ValidWingetID(r.ID) {
			continue
		}
		id, ok := EncodeID(SourceWinget, r.ID)
		if !ok {
			continue
		}
		name := software.Clean(strings.TrimSuffix(r.Name, "…"), 200)
		if name == "" {
			name = r.ID
		}
		res.Pending = append(res.Pending, protocol.PendingPatch{
			ID:             id,
			Title:          software.Clean(name+" "+r.Available, 256),
			Category:       CategoryApplication,
			Severity:       SeverityUnspecified,
			Source:         SourceWinget,
			CurrentVersion: software.Clean(r.Version, 128),
			NewVersion:     software.Clean(r.Available, 128),
		})
	}
	return res, nil
}

// Install implements Provider. winget upgrades one exact id per call.
func (p *WingetProvider) Install(ctx context.Context, req InstallRequest) (InstallOutcome, error) {
	good, bad, err := selectPending(ctx, p, req, true, software.ValidWingetID)
	if err != nil {
		return InstallOutcome{}, err
	}
	out := InstallOutcome{Items: bad}
	winget := p.Lookup("winget")
	for _, id := range good {
		if err := ctx.Err(); err != nil {
			out.Items = append(out.Items, item(SourceWinget, id, false, "not attempted: "+err.Error()))
			continue
		}
		code, _, err := runStream(ctx, p.Plat, req, platform.Command{
			Path: winget,
			Args: []string{"upgrade", "-e", "--id", id, "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"},
		})
		switch {
		case err != nil:
			out.Items = append(out.Items, item(SourceWinget, id, false, err.Error()))
		case code != 0:
			out.Items = append(out.Items, item(SourceWinget, id, false, fmt.Sprintf("winget exited with code %d", code)))
		default:
			out.Items = append(out.Items, item(SourceWinget, id, true, ""))
		}
	}
	return out, nil
}

// ---- Windows Update Agent ----

// WUAProvider handles Windows Update through the COM API (see wua.go).
type WUAProvider struct {
	Plat   platform.Platform
	Lookup software.Lookup
}

// Source implements Provider.
func (p *WUAProvider) Source() string { return SourceWUA }

// Optional implements Provider.
func (p *WUAProvider) Optional() bool { return false }

// Check implements Provider.
func (p *WUAProvider) Check(context.Context) error {
	if p.Lookup("powershell") == "" {
		return fmt.Errorf("powershell.exe: %w", errAbsent)
	}
	return nil
}

func (p *WUAProvider) command(script string, env []string) platform.Command {
	return platform.Command{Path: p.Lookup("powershell"), Args: PowerShellArgs, Env: env, Stdin: strings.NewReader(script)}
}

// Scan implements Provider.
func (p *WUAProvider) Scan(ctx context.Context, _ bool) (ScanResult, error) {
	var res ScanResult
	out, err := software.Output(ctx, p.Plat, scanTimeout, p.command(wuaScanScript, nil))
	if err != nil {
		return res, fmt.Errorf("search for Windows updates: %w", err)
	}
	scan, err := ParseWUAScan(out.Stdout)
	if err != nil {
		if out.ExitCode != 0 && strings.TrimSpace(out.Stdout) == "" {
			return res, fmt.Errorf("search for Windows updates: powershell exited with code %d: %s", out.ExitCode, software.Clean(out.Stderr, 200))
		}
		return res, err
	}
	res.Pending, res.RebootRequired, res.LastInstallAt = scan.Pending, scan.RebootRequired, scan.LastInstallAt
	return res, nil
}

// Install implements Provider.
func (p *WUAProvider) Install(ctx context.Context, req InstallRequest) (InstallOutcome, error) {
	var out InstallOutcome
	var env []string
	if req.All {
		env = []string{envWUAAll + "=1"}
	} else {
		good, bad := splitValid(SourceWUA, req.Names, ValidGUID)
		out.Items = bad
		if len(good) == 0 {
			return out, nil
		}
		env = []string{envWUAAll + "=0", envWUAIDs + "=" + strings.ToLower(strings.Join(good, ","))}
	}
	if req.Out != nil {
		fmt.Fprintln(req.Out, "> Windows Update Agent: download and install")
	}
	stdout := &software.LimitedBuffer{Limit: software.MaxToolStdout}
	cmd := p.command(wuaInstallScript, env)
	cmd.Stdout = stdout
	cmd.Stderr = req.Err
	code, err := p.Plat.Run(ctx, cmd)
	if err != nil {
		return out, fmt.Errorf("install Windows updates: %w", err)
	}
	res, err := ParseWUAInstall(stdout.String())
	if err != nil {
		if code != 0 && strings.TrimSpace(stdout.String()) == "" {
			return out, fmt.Errorf("install Windows updates: powershell exited with code %d", code)
		}
		return out, err
	}
	out.Items = append(out.Items, res.Items...)
	out.RebootRequired = res.RebootRequired
	return out, nil
}
