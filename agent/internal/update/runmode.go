package update

import (
	"flag"
	"io"
)

// RunMode reports, from the process arguments (os.Args), whether this process
// is the agent itself ("dranzo-agent run ...") and, if so, whether it runs in
// the foreground instead of under the service manager. It reads the same
// flags as the "run" command.
//
// Only a start of the agent counts as a start of a pending version; other
// commands that construct an agent ("enroll") must not arm the watchdog.
func RunMode(args []string) (running, foreground bool) {
	if len(args) < 2 || args[1] != "run" {
		return false, false
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("data-dir", "", "")
	fg := fs.Bool("foreground", false, "")
	fs.Bool("debug", false, "")
	if err := fs.Parse(args[2:]); err != nil {
		// The run command rejects the same arguments before an agent is built.
		return false, false
	}
	return true, *fg
}
