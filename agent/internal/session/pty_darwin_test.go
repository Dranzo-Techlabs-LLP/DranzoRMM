//go:build darwin

package session

import "testing"

type asUserMode struct {
	name  string
	setup func() (restore func())
}

func asUserModes() []asUserMode {
	return []asUserMode{{name: "launchctl asuser + sudo", setup: func() func() { return func() {} }}}
}

func TestParseDsclShell(t *testing.T) {
	if got := parseDsclShell("UserShell: /bin/zsh\n"); got != "/bin/zsh" {
		t.Errorf("got %q", got)
	}
	if got := parseDsclShell("No such key: UserShell\n"); got != "" {
		t.Errorf("got %q", got)
	}
}
