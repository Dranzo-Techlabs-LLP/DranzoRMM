package main

import (
	"path/filepath"

	"github.com/dranzo/dranzormm/agent/internal/agentcore"
	"github.com/dranzo/dranzormm/agent/internal/jobs/files"
	"github.com/dranzo/dranzormm/agent/internal/jobs/mesh"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/session"
	"github.com/dranzo/dranzormm/agent/internal/userui"
)

// Remote support (brief phase 6): remote sessions (terminal, files, desktop)
// with consent and the visible session indicator, the file browser jobs and
// the installation of the MeshCentral agent for remote desktop.
func init() {
	features = append(features, func(a *agentcore.Agent) error {
		env := a.Env()
		a.SetSessionHandler(session.New(env, userui.New(env.Platform), session.Options{}))

		a.Jobs().Register(protocol.KindFileList, files.List())
		a.Jobs().Register(protocol.KindFileRead, files.Read())
		a.Jobs().Register(protocol.KindFileWrite, files.Write())

		meshOpts := mesh.Options{Dir: filepath.Join(env.Paths.StateDir, mesh.DirName)}
		a.Jobs().Register(protocol.KindMeshInstall, mesh.Install(meshOpts))
		a.Jobs().Register(protocol.KindMeshUninstall, mesh.Uninstall(meshOpts))
		return nil
	})
}
