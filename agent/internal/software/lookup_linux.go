//go:build linux

package software

// systemToolDirs are root-owned on every supported distribution.
var systemToolDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin", "/snap/bin"}

// brewPaths is empty: Homebrew is only managed on macOS.
var brewPaths []string
