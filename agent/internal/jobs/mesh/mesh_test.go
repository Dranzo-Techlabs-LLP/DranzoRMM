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

// sampleSettings is shaped like MeshCentral's /meshsettings answer (CRLF,
// leading blank line, translations; ServerID shortened).
const sampleSettings = "\r\nMeshName=World Happiness Code\r\nMeshType=2\r\nMeshID=0xF529A416D16FECCAAF3F0A4E\r\nServerID=ABCDEF\r\nMeshServer=wss://mesh.example.com:443/agent.ashx\r\ntranslation={\"en\":{\"agent\":\"Agent\"}}\r\n"

func TestValidSettings(t *testing.T) {
	if !ValidSettings(sampleSettings) {
		t.Fatal("MeshCentral settings refused")
	}
	if !ValidSettings("MeshID=0x01\nMeshServer=local\n") {
		t.Error("LAN-only settings refused")
	}
	for name, s := range map[string]string{
		"empty":       "",
		"no server":   "MeshID=0x01\r\n",
		"no group":    "MeshServer=wss://mesh.example.com/agent.ashx\r\n",
		"empty group": "MeshID=0x\r\nMeshServer=wss://mesh.example.com/agent.ashx\r\n",
		"http server": "MeshID=0x01\r\nMeshServer=http://mesh.example.com/agent.ashx\r\n",
		"nul byte":    sampleSettings + "\x00",
		"not utf-8":   sampleSettings + "\xff",
		"too large":   sampleSettings + strings.Repeat("x", MaxSettingsBytes),
	} {
		if ValidSettings(s) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestValidateInstall(t *testing.T) {
	good := protocol.MeshInstallSpec{BlobID: protocol.NewID(), SHA256: strings.Repeat("ab", 32), SizeBytes: 4 << 20, FileName: "meshagent64-Example Group.exe"}
	if err := ValidateInstall(&good); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
	withSettings := good
	withSettings.MeshSettings = sampleSettings
	if err := ValidateInstall(&withSettings); err != nil {
		t.Fatalf("valid spec with settings refused: %v", err)
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
		"bad settings":   func(s *protocol.MeshInstallSpec) { s.MeshSettings = "rm -rf /" },
	} {
		spec := good
		mutate(&spec)
		if err := ValidateInstall(&spec); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
