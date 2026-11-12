package agentcore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// RegisterReporter adds a periodic report. interval is evaluated before every
// scheduling decision, so it follows the intervals announced by hello.ack.
// Each reporter runs once after the first hello.ack and then every interval
// while connected. Call before Run.
func (a *Agent) RegisterReporter(name string, interval func() time.Duration, collect ReporterFunc) {
	if name == "" || interval == nil || collect == nil {
		panic("agentcore: invalid reporter registration")
	}
	a.repMu.Lock()
	defer a.repMu.Unlock()
	for _, r := range a.reporters {
		if r.name == name {
			panic("agentcore: duplicate reporter " + name)
		}
	}
	a.reporters = append(a.reporters, &reporter{name: name, interval: interval, collect: collect, run: make(chan struct{}, 1)})
}

func (a *Agent) findReporter(name string) *reporter {
	a.repMu.Lock()
	defer a.repMu.Unlock()
	for _, r := range a.reporters {
		if r.name == name {
			return r
		}
	}
	return nil
}

// TriggerReporter collects and sends one report now (used by the
// "inventory.refresh", "software.scan", ... job kinds).
func (a *Agent) TriggerReporter(ctx context.Context, name string) error {
	r := a.findReporter(name)
	if r == nil {
		return fmt.Errorf("no reporter named %q", name)
	}
	return a.runReporter(ctx, r)
}

func (a *Agent) runReporter(ctx context.Context, r *reporter) error {
	// One collection of a given reporter at a time.
	select {
	case r.run <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-r.run }()

	started := time.Now()
	msgType, payload, err := r.collect(ctx)
	if err != nil {
		return fmt.Errorf("collect %s: %w", r.name, err)
	}
	if err := a.Send(ctx, msgType, payload); err != nil {
		return err
	}
	a.repMu.Lock()
	r.lastRun = time.Now()
	a.repMu.Unlock()
	a.log.Info("report sent", slog.String("reporter", r.name), slog.Duration("collect_duration", time.Since(started)))
	return nil
}

// reporterLoop runs due reporters while the connection is up.
func (a *Agent) reporterLoop(ctx context.Context) {
	for {
		a.repMu.Lock()
		list := append([]*reporter(nil), a.reporters...)
		a.repMu.Unlock()

		next := time.Hour
		for _, r := range list {
			interval := r.interval()
			if interval < time.Duration(config.MinReportSeconds)*time.Second {
				interval = time.Duration(config.MinReportSeconds) * time.Second
			}
			a.repMu.Lock()
			last := r.lastRun
			a.repMu.Unlock()
			due := last.IsZero() || time.Since(last) >= interval
			if due {
				if err := a.runReporter(ctx, r); err != nil {
					if ctx.Err() != nil {
						return
					}
					a.log.Warn("report failed", slog.String("reporter", r.name), slog.Any("error", err))
					// Do not retry a failing collector in a tight loop.
					a.repMu.Lock()
					r.lastRun = time.Now().Add(-interval + time.Minute)
					a.repMu.Unlock()
					if next > time.Minute {
						next = time.Minute
					}
					continue
				}
				last = time.Now()
			}
			if wait := time.Until(last.Add(interval)); wait < next {
				next = wait
			}
		}
		if next < time.Second {
			next = time.Second
		}
		t := time.NewTimer(next)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// ---- built-in job kinds ----

func (a *Agent) handleInventoryRefresh(jc *jobs.JobContext) jobs.Result {
	if err := a.TriggerReporter(jc.Ctx, ReporterInventory); err != nil {
		return jobs.Failed("%v", err)
	}
	return jobs.Succeeded()
}

// Bounds for the PBKDF2 parameters of an uninstall code.
const (
	minUninstallIterations = 100_000
	maxUninstallIterations = 10_000_000
)

// ValidateUninstallCode checks the PBKDF2-HMAC-SHA256 parameters of an
// uninstall-code verifier.
func ValidateUninstallCode(uc *protocol.UninstallCode) error {
	salt, err := base64.StdEncoding.DecodeString(uc.Salt)
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return errors.New("uninstallCode.salt must be base64 of 16 to 64 bytes")
	}
	hash, err := base64.StdEncoding.DecodeString(uc.Hash)
	if err != nil || len(hash) != sha256.Size {
		return errors.New("uninstallCode.hash must be base64 of 32 bytes")
	}
	if uc.Iterations < minUninstallIterations || uc.Iterations > maxUninstallIterations {
		return fmt.Errorf("uninstallCode.iterations must be between %d and %d", minUninstallIterations, maxUninstallIterations)
	}
	return nil
}

func (a *Agent) handleAgentConfigure(jc *jobs.JobContext) jobs.Result {
	// The key distinguishes "absent" (leave unchanged) from null (clear).
	var raw map[string]json.RawMessage
	if err := jc.DecodeSpec(&raw); err != nil {
		return jobs.Rejected("%v", err)
	}
	value, present := raw["uninstallCode"]
	if !present {
		return jobs.Succeeded()
	}
	var code *protocol.UninstallCode
	if string(value) != "null" {
		code = &protocol.UninstallCode{}
		if err := json.Unmarshal(value, code); err != nil {
			return jobs.Rejected("invalid uninstallCode")
		}
		if err := ValidateUninstallCode(code); err != nil {
			return jobs.Rejected("%v", err)
		}
	}
	a.cfgMu.Lock()
	a.cfg.UninstallCode = code
	cfg := a.cfg
	a.cfgMu.Unlock()
	if err := config.Save(a.paths, &cfg); err != nil {
		return jobs.Failed("save config: %v", err)
	}
	jc.Log.Info("uninstall code updated", slog.Bool("set", code != nil))
	return jobs.Succeeded()
}

func (a *Agent) handleAgentUninstall(jc *jobs.JobContext) jobs.Result {
	if a.opts.SelfUninstall == nil {
		return jobs.Unsupported("agent.uninstall needs the agent to run as an installed service")
	}
	jc.Log.Warn("agent uninstall requested by the server; the agent will remove itself after reporting")
	res := jobs.Succeeded()
	res.Message = "agent is removing itself"
	res.After = func() {
		// Give the writer a moment to put the result on the wire, then remove
		// the service. The service manager stops this process as part of it.
		time.Sleep(2 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := a.opts.SelfUninstall(ctx); err != nil {
			a.log.Error("self-uninstall failed", slog.Any("error", err))
		}
	}
	return res
}
