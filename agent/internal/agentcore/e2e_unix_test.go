//go:build !windows

package agentcore_test

const (
	scriptLanguage = "sh"
	// Prints to both streams, appends one line to the marker file, exits 3.
	markerScript = `echo "out:$1"
echo "err-line" 1>&2
echo ran >> "$MARKER"
exit 3
`
	sleepScript = "sleep 120\n"
)
