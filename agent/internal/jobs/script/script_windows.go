//go:build windows

package script

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func systemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// checkCmdArgs refuses arguments that cmd.exe would interpret (command
// separators, redirection, variable expansion, quotes). cmd.exe does not
// follow the normal argv quoting rules, so such characters cannot be passed
// safely to a batch file.
func checkCmdArgs(args []string) error {
	for _, a := range args {
		if strings.ContainsAny(a, "\"%&|<>^!()\r\n\t") {
			return errors.New("cmd script arguments must not contain any of \" % & | < > ^ ! ( ) or control characters")
		}
		for _, r := range a {
			if r < 0x20 {
				return errors.New("cmd script arguments must not contain control characters")
			}
		}
	}
	return nil
}

// resolveInterpreter maps a language to its interpreter on Windows.
func resolveInterpreter(language string, requireSigned bool) (*interpreter, error) {
	switch language {
	case protocol.LangPowerShell:
		// Windows PowerShell 5.1 ships with every supported Windows version.
		p := filepath.Join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if _, err := os.Stat(p); err != nil {
			return nil, unsupportedf("Windows PowerShell is not available")
		}
		policy := "Bypass"
		if requireSigned {
			// Only scripts signed by a publisher trusted on this machine run.
			policy = "AllSigned"
		}
		return &interpreter{
			path:   p,
			prefix: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", policy, "-File"},
			ext:    ".ps1",
			bom:    true,
		}, nil
	case protocol.LangCmd:
		p := filepath.Join(systemRoot(), "System32", "cmd.exe")
		return &interpreter{path: p, prefix: []string{"/D", "/C"}, ext: ".cmd", checkArgs: checkCmdArgs}, nil
	case protocol.LangPython:
		if p, err := exec.LookPath("python.exe"); err == nil {
			return &interpreter{path: p, ext: ".py"}, nil
		}
		if p, err := exec.LookPath("py.exe"); err == nil {
			return &interpreter{path: p, prefix: []string{"-3"}, ext: ".py"}, nil
		}
		return nil, unsupportedf("python is not installed")
	case protocol.LangBash, protocol.LangZsh, protocol.LangSh:
		return nil, unsupportedf("%s scripts do not run on Windows", language)
	}
	return nil, unsupportedf("language %s", language)
}
