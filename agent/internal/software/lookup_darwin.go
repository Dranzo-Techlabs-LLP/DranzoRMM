//go:build darwin

package software

// systemToolDirs are the SIP-protected directories of macOS. /usr/local/bin
// is deliberately absent: on Intel Macs it belongs to Homebrew's user.
var systemToolDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// brewPaths are the standard Homebrew locations (Apple Silicon, Intel).
var brewPaths = []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"}
