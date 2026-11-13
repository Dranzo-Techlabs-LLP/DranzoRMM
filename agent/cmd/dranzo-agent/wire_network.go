package main

import (
	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/netscan"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func init() { features = append(features, wireNetwork) }

// wireNetwork registers the network.scan job kind (PROTOCOL.md section 6.2).
func wireNetwork(a *agentcore.Agent) error {
	a.Jobs().Register(protocol.KindNetworkScan, netscan.Handler(netscan.New(a.Env().Platform)))
	return nil
}
