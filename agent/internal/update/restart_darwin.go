//go:build darwin

package update

// serviceRestartCommand: "launchctl kickstart -k system/<label>".
//
// launchd itself kills the running instance of the daemon (-k) and starts it
// again from the binary now on disk, so the restart does not depend on any
// process of ours surviving. Should the command fail, the caller re-executes
// the agent in place; and because the daemon is installed with KeepAlive,
// launchd starts it again whenever it exits.
func serviceRestartCommand(serviceName string) (string, []string, error) {
	launchctl, err := firstExisting("/bin/launchctl")
	if err != nil {
		return "", nil, err
	}
	return launchctl, []string{"kickstart", "-k", "system/" + serviceName}, nil
}
