//go:build windows

package software

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

func isFile(path string) bool {
	fi, err := os.Stat(path) //nolint:gosec // path is built from the System32 directory or the Program Files WindowsApps glob, never from server input
	return err == nil && fi.Mode().IsRegular()
}

// findWinget locates winget.exe. winget is a per-user app-execution alias, so
// the LocalSystem service usually has no "winget" on its PATH; the packaged
// executable under %ProgramFiles%\WindowsApps is used in that case (newest
// App Installer version first).
func findWinget() string {
	if p, err := exec.LookPath("winget.exe"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	programFiles := os.Getenv("ProgramW6432")
	if programFiles == "" {
		programFiles = os.Getenv("ProgramFiles")
	}
	if programFiles == "" {
		return ""
	}
	matches, err := filepath.Glob(filepath.Join(programFiles, "WindowsApps", "Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe", "winget.exe"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	sort.Slice(matches, func(i, j int) bool {
		return CompareVersions(filepath.Base(filepath.Dir(matches[i])), filepath.Base(filepath.Dir(matches[j]))) > 0
	})
	for _, m := range matches {
		if isFile(m) {
			return m
		}
	}
	return ""
}

// LookupTool returns the absolute path of a system tool, or "" when it is
// not installed. Windows' own tools are taken from the System32 directory,
// never from %PATH%.
func LookupTool(name string) string {
	if name == "" || strings.ContainsAny(name, `/\:`) {
		return ""
	}
	if name == "winget" {
		return findWinget()
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil || sys == "" {
		return ""
	}
	candidates := []string{filepath.Join(sys, name+".exe")}
	if name == "powershell" {
		candidates = []string{filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")}
	}
	for _, c := range candidates {
		if isFile(c) {
			return c
		}
	}
	return ""
}
