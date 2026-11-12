//go:build !windows

package script

import (
	"os/exec"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func lookFirst(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// resolveInterpreter maps a language to its interpreter on macOS and Linux.
func resolveInterpreter(language string, requireSigned bool) (*interpreter, error) {
	if requireSigned {
		return nil, unsupportedf("requireSignedPowerShell (signature-enforced PowerShell) is only available on Windows")
	}
	switch language {
	case protocol.LangSh:
		return &interpreter{path: "/bin/sh", ext: ".sh"}, nil
	case protocol.LangBash:
		p := lookFirst("bash", "/bin/bash", "/usr/bin/bash")
		if p == "" {
			return nil, unsupportedf("bash is not installed")
		}
		return &interpreter{path: p, ext: ".sh"}, nil
	case protocol.LangZsh:
		p := lookFirst("zsh", "/bin/zsh", "/usr/bin/zsh")
		if p == "" {
			return nil, unsupportedf("zsh is not installed")
		}
		return &interpreter{path: p, ext: ".zsh"}, nil
	case protocol.LangPython:
		p := lookFirst("python3", "/usr/bin/python3", "/usr/local/bin/python3", "python")
		if p == "" {
			return nil, unsupportedf("python is not installed")
		}
		return &interpreter{path: p, ext: ".py"}, nil
	case protocol.LangPowerShell:
		p := lookFirst("pwsh", "/usr/local/bin/pwsh", "/usr/bin/pwsh", "/opt/homebrew/bin/pwsh")
		if p == "" {
			return nil, unsupportedf("powershell scripts need PowerShell (pwsh), which is not installed")
		}
		return &interpreter{path: p, prefix: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File"}, ext: ".ps1"}, nil
	case protocol.LangCmd:
		return nil, unsupportedf("cmd scripts run only on Windows")
	}
	return nil, unsupportedf("language %s", language)
}
