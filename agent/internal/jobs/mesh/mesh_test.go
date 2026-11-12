package mesh

import (
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

const sampleNodeID = "Abc123@$Abc123@$Abc123@$Abc123@$Abc123@$Abc123@$Abc123@$Abc123@$"

func TestParseNodeID(t *testing.T) {
	hexID := strings.Repeat("fb", 48)
	cases := map[string]string{
		sampleNodeID + "\n":                      sampleNodeID,
		"\r\n  " + sampleNodeID + "  \r\n":       sampleNodeID,
		"MeshAgent starting...\n" + sampleNodeID: sampleNodeID,
		"node//" + sampleNodeID:                  sampleNodeID,
		"":                                       "",
		"not installed":                          "",
		sampleNodeID[:63]:                        "",
		sampleNodeID + "x":                       "",
		strings.Replace(sampleNodeID, "@", "+", 1):   "",
		"$(reboot)" + sampleNodeID[9:]:               "",
		sampleNodeID + "\nError: database is locked": sampleNodeID,
	}
	for in, want := range cases {
		if got := ParseNodeID(in); got != want {
			t.Errorf("ParseNodeID(%q) = %q, want %q", in, got, want)
		}
	}
	got := ParseNodeID(hexID)
	if len(got) != 64 || strings.ContainsAny(got, "+/=") || !nodeIDBase64.MatchString(got) {
		t.Errorf("hexadecimal node id converted to %q", got)
	}
	if NodeID(sampleNodeID) != "node//"+sampleNodeID || NodeID("") != "" {
		t.Error("NodeID format")
	}
}

func TestValidateInstall(t *testing.T) {
	good := protocol.MeshInstallSpec{BlobID: protocol.NewID(), SHA256: strings.Repeat("ab", 32), SizeBytes: 4 << 20, FileName: "meshagent64-Example Group.exe"}
	if err := ValidateInstall(&good); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.MeshInstallSpec){
		"blob id":        func(s *protocol.MeshInstallSpec) { s.BlobID = "1" },
		"sha256":         func(s *protocol.MeshInstallSpec) { s.SHA256 = "abc" },
		"zero size":      func(s *protocol.MeshInstallSpec) { s.SizeBytes = 0 },
		"huge size":      func(s *protocol.MeshInstallSpec) { s.SizeBytes = MaxBinaryBytes + 1 },
		"empty name":     func(s *protocol.MeshInstallSpec) { s.FileName = "" },
		"path in name":   func(s *protocol.MeshInstallSpec) { s.FileName = "../../etc/cron.d/x" },
		"windows path":   func(s *protocol.MeshInstallSpec) { s.FileName = `C:\Windows\x.exe` },
		"option as name": func(s *protocol.MeshInstallSpec) { s.FileName = "-fulluninstall" },
		"control chars":  func(s *protocol.MeshInstallSpec) { s.FileName = "mesh\nagent" },
	} {
		spec := good
		mutate(&spec)
		if err := ValidateInstall(&spec); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
