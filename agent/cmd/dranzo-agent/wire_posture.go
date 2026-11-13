package main

import (
	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/jobs/policy"
	"github.com/dranzo/dranzormm/agent/internal/posture"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func init() { features = append(features, wirePosture) }

// wirePosture registers the security posture reporter (PROTOCOL.md section
// 7.3) and the "posture.scan" and "policy.evaluate" job kinds.
func wirePosture(a *agentcore.Agent) error {
	env := a.Env()
	collector := posture.New(env.Platform, env.Log)
	a.RegisterReporter(posture.ReporterName, a.PostureInterval, posture.Reporter(collector))
	a.Jobs().Register(protocol.KindPostureScan, jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
		if err := a.TriggerReporter(jc.Ctx, posture.ReporterName); err != nil {
			return jobs.Failed("%v", err)
		}
		return jobs.Succeeded()
	}))
	fw := firewallManager(env.Platform, env.Paths, func() string { return a.Config().ServerURL })
	a.Jobs().Register(protocol.KindPolicyEvaluate, policy.New(collector, env.Platform).WithFirewall(fw))
	return nil
}
