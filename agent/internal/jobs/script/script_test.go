package script

import (
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func TestValidate(t *testing.T) {
	ok := func() protocol.ScriptSpec {
		return protocol.ScriptSpec{Language: "sh", Body: "echo hi", RunAs: "system"}
	}
	s := ok()
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	// runAs defaults to system.
	s = ok()
	s.RunAs = ""
	if err := Validate(&s); err != nil || s.RunAs != "system" {
		t.Fatalf("%v %q", err, s.RunAs)
	}
	cases := map[string]func(*protocol.ScriptSpec){
		"unknown language":       func(s *protocol.ScriptSpec) { s.Language = "perl" },
		"empty language":         func(s *protocol.ScriptSpec) { s.Language = "" },
		"empty body":             func(s *protocol.ScriptSpec) { s.Body = "" },
		"oversized body":         func(s *protocol.ScriptSpec) { s.Body = strings.Repeat("a", MaxBodyBytes+1) },
		"NUL in body":            func(s *protocol.ScriptSpec) { s.Body = "echo\x00hi" },
		"too many args":          func(s *protocol.ScriptSpec) { s.Args = make([]string, MaxArgs+1) },
		"oversized arg":          func(s *protocol.ScriptSpec) { s.Args = []string{strings.Repeat("a", MaxArgBytes+1)} },
		"NUL in arg":             func(s *protocol.ScriptSpec) { s.Args = []string{"a\x00b"} },
		"env name with =":        func(s *protocol.ScriptSpec) { s.Env = map[string]string{"A=B": "x"} },
		"env name with space":    func(s *protocol.ScriptSpec) { s.Env = map[string]string{"A B": "x"} },
		"env name leading digit": func(s *protocol.ScriptSpec) { s.Env = map[string]string{"1A": "x"} },
		"env name empty":         func(s *protocol.ScriptSpec) { s.Env = map[string]string{"": "x"} },
		"env name too long":      func(s *protocol.ScriptSpec) { s.Env = map[string]string{strings.Repeat("A", 65): "x"} },
		"env value NUL":          func(s *protocol.ScriptSpec) { s.Env = map[string]string{"A": "x\x00y"} },
		"env value too long":     func(s *protocol.ScriptSpec) { s.Env = map[string]string{"A": strings.Repeat("v", MaxEnvValueBytes+1)} },
		"bad runAs":              func(s *protocol.ScriptSpec) { s.RunAs = "root" },
		"signed flag on bash":    func(s *protocol.ScriptSpec) { s.RequireSignedPowerShell = true },
	}
	for name, mut := range cases {
		s := ok()
		mut(&s)
		if err := Validate(&s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The validation message never echoes the body or values.
	s = ok()
	s.Env = map[string]string{"A": "secret\x00value"}
	if err := Validate(&s); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("validation error leaks a value: %v", err)
	}
}
