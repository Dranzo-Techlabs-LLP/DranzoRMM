// Package patch implements patch management (PROTOCOL.md sections 6.2 and
// 7.4): the "patch.state" report, the "patch.scan" job kind that triggers it
// and the "patch.install" job kind with its reboot policy.
//
// Update sources: the Windows Update Agent COM API and winget on Windows,
// softwareupdate and Homebrew on macOS, apt and dnf on Linux. Every source
// is driven through its own command-line tool with argv arrays; parsers of
// tool output are in untagged files and are tested with fixtures.
package patch

import (
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Update sources (PendingPatch.Source, PatchInstallSpec.Sources).
const (
	SourceWUA            = "wua"
	SourceSoftwareUpdate = "softwareupdate"
	SourceApt            = "apt"
	SourceDnf            = "dnf"
	SourceWinget         = "winget"
	SourceBrew           = "brew"
)

// AllSources lists every source of the protocol.
var AllSources = []string{SourceWUA, SourceSoftwareUpdate, SourceApt, SourceDnf, SourceWinget, SourceBrew}

// Categories and severities reported in patch.state. The protocol leaves the
// vocabulary open; these are the values this agent uses on every OS so that
// patch policies can match on them.
const (
	CategorySecurity    = "security"
	CategoryCritical    = "critical"
	CategoryDefinition  = "definition"
	CategoryDriver      = "driver"
	CategoryFeature     = "feature"
	CategoryRollup      = "rollup"
	CategoryServicePack = "servicepack"
	CategoryTool        = "tool"
	CategoryUpdate      = "update"
	CategoryApplication = "application"

	SeverityCritical    = "critical"
	SeverityImportant   = "important"
	SeverityModerate    = "moderate"
	SeverityLow         = "low"
	SeverityUnspecified = "unspecified"
)

const hexDigits = "0123456789ABCDEF"

func idLiteral(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '.', c == '_', c == '/', c == '-':
		return true
	}
	return false
}

// EncodeID builds the update id "<source>:<name>" used in patch.state and
// patch.install. Update ids must match the packageId pattern of PROTOCOL.md
// section 6.2, but native names do not always (macOS labels contain
// spaces), so every byte of name outside [A-Za-z0-9+._/-] is written as "@"
// followed by two upper-case hex digits. ok is false when the result would
// not be a valid id (empty name, too long).
func EncodeID(source, name string) (id string, ok bool) {
	if name == "" {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(source) + 1 + len(name))
	b.WriteString(source)
	b.WriteByte(':')
	for i := 0; i < len(name); i++ {
		c := name[i]
		if idLiteral(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('@')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0F])
	}
	id = b.String()
	return id, protocol.ValidPackageID(id)
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// DecodeID splits an update id into its source and native name. ok is false
// for anything EncodeID could not have produced.
func DecodeID(id string) (source, name string, ok bool) {
	if !protocol.ValidPackageID(id) || strings.HasPrefix(id, "-") {
		return "", "", false
	}
	source, enc, found := strings.Cut(id, ":")
	if !found || enc == "" {
		return "", "", false
	}
	known := false
	for _, s := range AllSources {
		known = known || s == source
	}
	if !known {
		return "", "", false
	}
	var b strings.Builder
	b.Grow(len(enc))
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		switch {
		case idLiteral(c):
			b.WriteByte(c)
		case c == '@' && i+2 < len(enc):
			hi, ok1 := unhex(enc[i+1])
			lo, ok2 := unhex(enc[i+2])
			if !ok1 || !ok2 {
				return "", "", false
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
		default:
			return "", "", false
		}
	}
	return source, b.String(), true
}
