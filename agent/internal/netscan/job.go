package netscan

import (
	"log/slog"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Handler is the network.scan job kind.
func Handler(s *Scanner) jobs.Handler {
	return jobs.HandlerFunc(func(jc *jobs.JobContext) jobs.Result {
		var spec protocol.NetworkScanSpec
		if err := jc.DecodeSpec(&spec); err != nil {
			return jobs.Rejected("%v", err)
		}
		res, err := s.Run(jc.Ctx, spec.ResolveNames)
		if err != nil {
			return jobs.Failed("network scan: %v", err)
		}
		if jc.Log != nil {
			jc.Log.Info("network.scan", slog.Any("subnets", res.Subnets), slog.Int("neighbors", len(res.Neighbors)), slog.Bool("truncated", res.Truncated))
		}
		r := jobs.SucceededWith(res)
		if len(res.Subnets) == 0 {
			r.Message = "no private IPv4 network to scan on this device"
		}
		return r
	})
}
