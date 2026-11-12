package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/pkginstall"
	"github.com/dranzo/dranzormm/agent/internal/jobs/reboot"
	"github.com/dranzo/dranzormm/agent/internal/jobs/swdeploy"
	"github.com/dranzo/dranzormm/agent/internal/patch"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

func init() { features = append(features, wireSoftware) }

// wireSoftware registers software inventory, software and package
// deployment, patch management and the reboot job kind
// (internal/software, internal/jobs/swdeploy, internal/jobs/pkginstall,
// internal/patch, internal/jobs/reboot).
func wireSoftware(a *agentcore.Agent) error {
	env := a.Env()

	// Reports: software.inventory and patch.state, plus the job kinds that
	// trigger them on demand.
	inventory := software.NewCollector(env.Platform)
	a.RegisterReporter(software.ReporterName, a.SoftwareInterval, func(ctx context.Context) (string, any, error) {
		return protocol.TypeSoftwareInventory, inventory.Collect(ctx), nil
	})
	scanner := patch.NewScanner(env.Platform)
	a.RegisterReporter(patch.ReporterName, a.PatchScanInterval, func(ctx context.Context) (string, any, error) {
		return protocol.TypePatchState, scanner.Collect(ctx), nil
	})
	trigger := func(name string) jobs.Handler {
		return jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
			if err := a.TriggerReporter(jc.Ctx, name); err != nil {
				return jobs.Failed("%v", err)
			}
			return jobs.Succeeded()
		})
	}
	a.Jobs().Register(protocol.KindSoftwareScan, trigger(software.ReporterName))
	a.Jobs().Register(protocol.KindPatchScan, trigger(patch.ReporterName))

	// Deployment.
	a.Jobs().Register(protocol.KindSoftwareInstall, swdeploy.NewInstall())
	a.Jobs().Register(protocol.KindSoftwareUninstall, swdeploy.NewUninstall())
	a.Jobs().Register(protocol.KindPackageInstall, pkginstall.NewInstall())
	a.Jobs().Register(protocol.KindPackageUninstall, pkginstall.NewUninstall())

	// Patching and restarts. The user interface asks and informs the
	// logged-in user; the scheduler keeps a pending restart in memory.
	ui := userui.New(env.Platform)
	rebooter := reboot.NewRebooter(env.Platform)
	scheduler := reboot.NewScheduler(ui, rebooter, env.Platform, env.Log)
	refresh := func() {
		// A fresh patch.state after an installation, so the dashboard does
		// not wait for the next periodic scan.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
			defer cancel()
			if err := a.TriggerReporter(ctx, patch.ReporterName); err != nil {
				env.Log.Warn("patch state report after installation failed", slog.Any("error", err))
			}
		}()
	}
	a.Jobs().Register(protocol.KindPatchInstall, patch.NewInstallHandler(scanner, scheduler, refresh))
	a.Jobs().Register(protocol.KindReboot, reboot.NewHandler(ui, rebooter))
	return nil
}
