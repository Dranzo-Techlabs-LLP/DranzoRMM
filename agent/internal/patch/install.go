package patch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/reboot"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Reboot policy modes.
const (
	RebootNever      = "never"
	RebootIfRequired = "if_required"
	RebootForce      = "force"
)

// Limits of a patch.install spec.
const (
	MaxUpdateIDs       = 500
	MaxDeferrals       = 24
	MaxDeadlineMinutes = 7 * 24 * 60
)

// RebootScheduler is the part of reboot.Scheduler the handler uses.
type RebootScheduler interface {
	Schedule(p reboot.Plan) (done <-chan struct{}, started bool)
}

// InstallHandler implements the "patch.install" job kind.
type InstallHandler struct {
	Scanner   *Scanner
	Scheduler RebootScheduler
	// OSName is used in "not supported" messages.
	OSName string
	// AfterInstall, if set, is called once the installation is over (the
	// agent uses it to send a fresh patch.state report).
	AfterInstall func()
}

// NewInstallHandler returns the patch.install handler for this OS.
func NewInstallHandler(scanner *Scanner, scheduler RebootScheduler, afterInstall func()) *InstallHandler {
	return &InstallHandler{Scanner: scanner, Scheduler: scheduler, OSName: osName, AfterInstall: afterInstall}
}

func knownSource(s string) bool {
	for _, k := range AllSources {
		if k == s {
			return true
		}
	}
	return false
}

// ValidateInstall checks every field of the spec and normalises it (an
// empty reboot mode means "never", duplicate sources are dropped).
func ValidateInstall(spec *protocol.PatchInstallSpec) error {
	if len(spec.UpdateIDs) > MaxUpdateIDs {
		return fmt.Errorf("more than %d updateIds", MaxUpdateIDs)
	}
	for _, id := range spec.UpdateIDs {
		if strings.HasPrefix(id, "-") || !protocol.ValidPackageID(id) {
			return errors.New("updateIds contains an invalid update id")
		}
	}
	if len(spec.Sources) > len(AllSources) {
		return errors.New("too many sources")
	}
	seen := map[string]bool{}
	sources := spec.Sources[:0:0]
	for _, s := range spec.Sources {
		if !knownSource(s) {
			return errors.New("sources must be chosen from wua, softwareupdate, apt, dnf, winget, brew")
		}
		if !seen[s] {
			seen[s] = true
			sources = append(sources, s)
		}
	}
	spec.Sources = sources
	if spec.UpdateIDs == nil && len(spec.Sources) == 0 {
		return errors.New("sources is required when updateIds is null (install everything pending)")
	}
	switch spec.Reboot.Mode {
	case "":
		spec.Reboot.Mode = RebootNever
	case RebootNever, RebootIfRequired, RebootForce:
	default:
		return errors.New("reboot.mode must be never, if_required or force")
	}
	if spec.Reboot.Deferrals < 0 || spec.Reboot.Deferrals > MaxDeferrals {
		return fmt.Errorf("reboot.deferrals must be between 0 and %d", MaxDeferrals)
	}
	if spec.Reboot.DeadlineMinutes < 0 || spec.Reboot.DeadlineMinutes > MaxDeadlineMinutes {
		return fmt.Errorf("reboot.deadlineMinutes must be between 0 and %d", MaxDeadlineMinutes)
	}
	if err := reboot.ValidMessage(spec.Reboot.Message); err != nil {
		return fmt.Errorf("reboot.%w", err)
	}
	return nil
}

func hasSource(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Handle implements jobs.Handler.
func (h *InstallHandler) Handle(jc *jobs.JobContext) jobs.Result {
	var spec protocol.PatchInstallSpec
	if err := jc.DecodeSpec(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	if err := ValidateInstall(&spec); err != nil {
		return jobs.Rejected("%v", err)
	}
	all := spec.UpdateIDs == nil
	jc.Log.Info("patch install",
		slog.Bool("all_pending", all),
		slog.Int("update_count", len(spec.UpdateIDs)),
		slog.String("sources", strings.Join(spec.Sources, ",")),
		slog.String("reboot_mode", spec.Reboot.Mode))

	// Work per source, in the order of this OS's providers.
	names := map[string][]string{}
	var early []protocol.PatchInstallItem // ids that cannot be attempted at all
	anyHere := false
	if all {
		for _, s := range spec.Sources {
			if h.Scanner.Provider(s) != nil {
				names[s] = nil
				anyHere = true
			}
		}
		if !anyHere {
			return jobs.Unsupported("none of the requested update sources (%s) exist on %s", strings.Join(spec.Sources, ", "), h.OSName)
		}
	} else {
		for _, id := range spec.UpdateIDs {
			source, name, ok := DecodeID(id)
			switch {
			case !ok:
				early = append(early, protocol.PatchInstallItem{ID: id, Error: "not an update id reported by this agent"})
			case len(spec.Sources) > 0 && !hasSource(spec.Sources, source):
				early = append(early, protocol.PatchInstallItem{ID: id, Error: "the update's source is not among the job's sources"})
			case h.Scanner.Provider(source) == nil:
				early = append(early, protocol.PatchInstallItem{ID: id, Error: fmt.Sprintf("not supported on this OS: update source %s does not exist on %s", source, h.OSName)})
			default:
				names[source] = append(names[source], name)
				anyHere = true
			}
		}
		if !anyHere && len(spec.UpdateIDs) > 0 {
			onlyForeign := true
			for _, it := range early {
				onlyForeign = onlyForeign && strings.HasPrefix(it.Error, "not supported on this OS")
			}
			if onlyForeign {
				return jobs.Unsupported("the requested updates belong to update sources that do not exist on %s", h.OSName)
			}
		}
	}

	items := early
	rebootRequired := false
	var restarts []func(ctx context.Context) error
	for _, p := range h.Scanner.Providers() {
		wanted, selected := names[p.Source()]
		if !selected {
			continue
		}
		fail := func(reason string) {
			if all {
				fmt.Fprintf(jc.Stderr, "%s: %s\n", p.Source(), reason)
				items = append(items, protocol.PatchInstallItem{ID: p.Source() + ":all", Error: reason})
				return
			}
			items = append(items, failAll(p.Source(), wanted, reason)...)
		}
		if err := jc.Ctx.Err(); err != nil {
			fail("not attempted: " + err.Error())
			continue
		}
		if err := p.Check(jc.Ctx); err != nil {
			fail(fmt.Sprintf("update source %s cannot be used: %v", p.Source(), err))
			continue
		}
		fmt.Fprintf(jc.Stdout, "== %s ==\n", p.Source())
		outcome, err := p.Install(jc.Ctx, InstallRequest{All: all, Names: wanted, Out: jc.Stdout, Err: jc.Stderr})
		items = append(items, outcome.Items...)
		if err != nil {
			// Whatever was not reported individually failed with this error.
			if all {
				fail(err.Error())
			} else {
				reported := map[string]bool{}
				for _, it := range outcome.Items {
					reported[it.ID] = true
				}
				var missing []string
				for _, n := range wanted {
					if id, _ := EncodeID(p.Source(), n); !reported[id] {
						missing = append(missing, n)
					}
				}
				items = append(items, failAll(p.Source(), missing, err.Error())...)
			}
		}
		rebootRequired = rebootRequired || outcome.RebootRequired
		if outcome.Restart != nil {
			restarts = append(restarts, outcome.Restart)
		}
	}
	if !all {
		items = orderItems(spec.UpdateIDs, items)
	}
	if items == nil {
		items = []protocol.PatchInstallItem{}
	}
	if jc.Platform != nil {
		pctx, cancel := context.WithTimeout(context.WithoutCancel(jc.Ctx), time.Minute)
		if pending, err := jc.Platform.PendingReboot(pctx); err == nil && pending {
			rebootRequired = true
		}
		cancel()
	}

	failed := 0
	for _, it := range items {
		if it.OK {
			fmt.Fprintf(jc.Stdout, "installed: %s\n", it.ID)
		} else {
			failed++
			fmt.Fprintf(jc.Stdout, "FAILED:    %s (%s)\n", it.ID, it.Error)
		}
	}
	res := jobs.Result{
		Status: protocol.StatusSucceeded,
		Result: protocol.PatchInstallResult{Installed: items, RebootRequired: rebootRequired},
	}
	switch {
	case failed > 0:
		res.Status = protocol.StatusFailed
		res.Message = fmt.Sprintf("%d of %d updates failed", failed, len(items))
	case len(items) == 0:
		res.Message = "no pending updates"
	default:
		res.Message = fmt.Sprintf("%d updates installed", len(items))
	}

	restart := spec.Reboot.Mode == RebootForce || (spec.Reboot.Mode == RebootIfRequired && rebootRequired)
	switch {
	case restart && h.Scheduler == nil:
		fmt.Fprintln(jc.Stdout, "A restart is needed but this agent build cannot restart the computer.")
	case restart:
		fmt.Fprintf(jc.Stdout, "Restart policy %s: the computer restarts within %d minutes (deferrals allowed: %d).\n",
			spec.Reboot.Mode, spec.Reboot.DeadlineMinutes, spec.Reboot.Deferrals)
		res.Message += "; restart scheduled"
	case rebootRequired:
		fmt.Fprintln(jc.Stdout, "A restart is required to finish the installation (reboot policy: never).")
		res.Message += "; restart required"
	}

	plan := reboot.Plan{
		NotifyUser: spec.Reboot.NotifyUser,
		Deferrals:  spec.Reboot.Deferrals,
		Deadline:   time.Duration(spec.Reboot.DeadlineMinutes) * time.Minute,
		Message:    spec.Reboot.Message,
		Restart:    chainRestarts(restarts),
	}
	log := jc.Log
	// Runs after the job result was handed to the connection, so the server
	// always learns the outcome before the machine restarts.
	res.After = func() {
		if restart && h.Scheduler != nil {
			if _, started := h.Scheduler.Schedule(plan); !started {
				log.Info("a restart with an earlier deadline is already pending")
			}
		}
		if h.AfterInstall != nil {
			h.AfterInstall()
		}
	}
	return res
}

// chainRestarts combines the restart actions of several sources: the first
// one that succeeds restarts the machine.
func chainRestarts(fns []func(ctx context.Context) error) func(ctx context.Context) error {
	if len(fns) == 0 {
		return nil
	}
	return func(ctx context.Context) error {
		var last error
		for _, fn := range fns {
			if last = fn(ctx); last == nil {
				return nil
			}
		}
		return last
	}
}

// orderItems returns the items in the order of the requested ids, with any
// extra items (never expected) at the end.
func orderItems(ids []string, items []protocol.PatchInstallItem) []protocol.PatchInstallItem {
	byID := make(map[string]protocol.PatchInstallItem, len(items))
	for _, it := range items {
		if _, dup := byID[it.ID]; !dup {
			byID[it.ID] = it
		}
	}
	out := make([]protocol.PatchInstallItem, 0, len(items))
	used := map[string]bool{}
	for _, id := range ids {
		if used[id] {
			continue
		}
		used[id] = true
		if it, ok := byID[id]; ok {
			out = append(out, it)
		} else {
			out = append(out, protocol.PatchInstallItem{ID: id, Error: "no result was reported for this update"})
		}
	}
	for _, it := range items {
		if !used[it.ID] {
			used[it.ID] = true
			out = append(out, it)
		}
	}
	return out
}
