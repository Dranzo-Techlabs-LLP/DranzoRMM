//go:build linux

package session

import (
	"errors"
	"testing"
)

type asUserMode struct {
	name  string
	setup func() (restore func())
}

// asUserModes exercises both ways of becoming the user on Linux.
func asUserModes() []asUserMode {
	return []asUserMode{
		{name: "runuser", setup: func() func() { return func() {} }},
		{name: "direct credentials", setup: func() func() {
			old := lookRunuser
			lookRunuser = func() (string, error) { return "", errors.New("not installed") }
			return func() { lookRunuser = old }
		}},
	}
}

func TestParseProcStat(t *testing.T) {
	p, ok := parseProcStat(4321, "4321 (weird) name (x)) S 77 4321 99 34816 4321 4194304 1 2 3")
	if !ok || p.pid != 4321 || p.ppid != 77 || p.sid != 99 {
		t.Errorf("parseProcStat = %+v, %v", p, ok)
	}
	if _, ok := parseProcStat(1, "garbage"); ok {
		t.Error("garbage accepted")
	}
}
