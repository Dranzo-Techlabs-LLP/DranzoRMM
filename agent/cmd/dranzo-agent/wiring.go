package main

import "github.com/dranzo/dranzormm/agent/internal/agentcore"

// features is the list of optional feature modules. Each module adds itself
// from an init function in its own wire_<module>.go file in this package, so
// modules can be added without editing main.go.
var features []func(a *agentcore.Agent) error
