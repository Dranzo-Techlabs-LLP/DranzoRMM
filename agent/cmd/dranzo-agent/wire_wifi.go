package main

import (
	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/wifi"
)

func init() { features = append(features, wireWifi) }

// wireWifi registers the 802.1X enrollment kinds (PROTOCOL.md section 6.2).
func wireWifi(a *agentcore.Agent) error {
	env := a.Env()
	for kind, h := range wifi.Handlers(wifi.NewEnroller(env.Platform, env.Paths.StateDir)) {
		a.Jobs().Register(kind, h)
	}
	return nil
}
