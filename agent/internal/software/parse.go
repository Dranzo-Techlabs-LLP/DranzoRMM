package software

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Field limits of a reported item.
const (
	maxNameBytes      = 256
	maxVersionBytes   = 128
	maxPublisherBytes = 256
	maxIDBytes        = 256
)

func unixDate(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02")
}

// ---- Windows: uninstall registry keys ----

// RegistryEntry is one subkey of an
// HKLM\SOFTWARE\[WOW6432Node\]Microsoft\Windows\CurrentVersion\Uninstall key
// with the values the inventory needs.
type RegistryEntry struct {
	// Key is the subkey name (a product code GUID or a free-form name).
	Key string `json:"key"`
	// View is "64" or "32" (the WOW6432Node view).
	View            string `json:"view"`
	DisplayName     string `json:"displayName"`
	DisplayVersion  string `json:"displayVersion"`
	Publisher       string `json:"publisher"`
	InstallDate     string `json:"installDate"`
	ParentKeyName   string `json:"parentKeyName"`
	ReleaseType     string `json:"releaseType"`
	SystemComponent uint64 `json:"systemComponent"`
}

// registryDate turns the registry's YYYYMMDD into YYYY-MM-DD ("" if it is
// anything else).
func registryDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) != 8 {
		return ""
	}
	t, err := time.Parse("20060102", s)
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02")
}

// RegistryItems converts uninstall entries to inventory items. Entries
// without a DisplayName, system components and patches of another product
// (ParentKeyName / update release types) are not programs a technician would
// recognise and are skipped, as Windows' own "Installed apps" list does.
func RegistryItems(entries []RegistryEntry) []protocol.SoftwareItem {
	items := make([]protocol.SoftwareItem, 0, len(entries))
	for _, e := range entries {
		name := Clean(e.DisplayName, maxNameBytes)
		if name == "" || e.SystemComponent == 1 || strings.TrimSpace(e.ParentKeyName) != "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(e.ReleaseType)) {
		case "security update", "update rollup", "hotfix", "update", "service pack":
			continue
		}
		items = append(items, protocol.SoftwareItem{
			Name:        name,
			Version:     Clean(e.DisplayVersion, maxVersionBytes),
			Publisher:   Clean(e.Publisher, maxPublisherBytes),
			Source:      protocol.SourceRegistry,
			ID:          Clean(e.Key, maxIDBytes),
			InstallDate: registryDate(e.InstallDate),
		})
	}
	return items
}

// ---- Windows: winget tables ----

// WingetRow is one row of a "winget list" / "winget upgrade" table.
type WingetRow struct {
	Name      string
	ID        string
	Version   string
	Available string
	Source    string
}

func isDashLine(l string) bool {
	l = strings.TrimSpace(l)
	return len(l) >= 10 && strings.Trim(l, "-") == ""
}

// runeWidth is the number of terminal columns winget assumes for r (it pads
// East Asian wide characters as two columns).
func runeWidth(r rune) int {
	switch {
	case r < 0x1100:
		return 1
	case r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0xA4CF, // CJK, Kana, Yi
		r >= 0xAC00 && r <= 0xD7A3, // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF, // CJK compatibility ideographs
		r >= 0xFE30 && r <= 0xFE6F, // CJK compatibility forms
		r >= 0xFF00 && r <= 0xFF60, // fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1FAFF, // emoji
		r >= 0x20000 && r <= 0x3FFFD:
		return 2
	}
	return 1
}

type wingetColumn struct {
	start int
	title string
}

// headerColumns returns the display column at which each header word starts.
func headerColumns(header string) []wingetColumn {
	var cols []wingetColumn
	col := 0
	prevSpace := true
	var title strings.Builder
	for _, r := range header {
		space := r == ' ' || r == '\t'
		if !space && prevSpace {
			if len(cols) > 0 {
				cols[len(cols)-1].title = title.String()
			}
			title.Reset()
			cols = append(cols, wingetColumn{start: col})
		}
		if !space {
			title.WriteRune(r)
		}
		prevSpace = space
		col += runeWidth(r)
	}
	if len(cols) > 0 {
		cols[len(cols)-1].title = title.String()
	}
	return cols
}

// cutColumns slices a table row at the header's display columns.
func cutColumns(line string, cols []wingetColumn) []string {
	parts := make([]strings.Builder, len(cols))
	col, idx := 0, 0
	for _, r := range line {
		for idx+1 < len(cols) && col >= cols[idx+1].start {
			idx++
		}
		_, _ = parts[idx].WriteRune(r) // strings.Builder never fails
		col += runeWidth(r)
	}
	fields := make([]string, len(cols))
	for i := range parts {
		fields[i] = strings.TrimSpace(parts[i].String())
	}
	return fields
}

func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return (c >= '0' && c <= '9') || c == '<' || c == '>'
}

// ParseWingetTable extracts the rows of every table in the output of
// "winget list" or "winget upgrade". winget has no machine-readable output
// for these commands, so the parser is defensive: it locates each table by
// its dashed separator line, takes the column positions from the header line
// above it (whatever the header language), slices rows by display width, and
// ignores progress spinners, banners and summary lines.
func ParseWingetTable(output string) []WingetRow {
	lines := Lines(output)
	var rows []WingetRow
	for i := 1; i < len(lines); i++ {
		if !isDashLine(lines[i]) {
			continue
		}
		cols := headerColumns(lines[i-1])
		if len(cols) < 3 {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if strings.TrimSpace(l) == "" || isDashLine(l) {
				break
			}
			if j+1 < len(lines) && isDashLine(lines[j+1]) {
				break // header of the next table
			}
			f := cutColumns(l, cols)
			row := WingetRow{Name: f[0], ID: f[1], Version: f[2]}
			for k := 3; k < len(cols); k++ {
				switch title := strings.ToLower(cols[k].title); {
				case title == "available":
					row.Available = f[k]
				case title == "source":
					row.Source = f[k]
				case len(cols) >= 5 && k == 3:
					row.Available = f[k]
				case len(cols) >= 5 && k == 4:
					row.Source = f[k]
				case looksLikeVersion(f[k]):
					row.Available = f[k]
				default:
					row.Source = f[k]
				}
			}
			// Summary lines ("3 upgrades available.") and wrapped text do not
			// have a well-formed id and version.
			if row.ID == "" || row.Version == "" || strings.ContainsAny(row.ID, " \t") || strings.ContainsAny(row.Version, " \t") {
				continue
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// WingetItems converts "winget list" rows to inventory items. Rows whose id
// starts with "ARP\" are the registry (Add/Remove Programs) entries winget
// could not match to a catalogue package; the registry collector already
// reports those, so they are skipped here.
func WingetItems(rows []WingetRow) []protocol.SoftwareItem {
	items := make([]protocol.SoftwareItem, 0, len(rows))
	for _, r := range rows {
		if strings.HasPrefix(strings.ToUpper(r.ID), `ARP\`) {
			continue
		}
		name := Clean(strings.TrimSuffix(r.Name, "…"), maxNameBytes)
		if name == "" {
			name = r.ID
		}
		items = append(items, protocol.SoftwareItem{
			Name:    name,
			Version: Clean(r.Version, maxVersionBytes),
			Source:  protocol.SourceWinget,
			ID:      Clean(r.ID, maxIDBytes),
		})
	}
	return items
}

// ---- macOS: application bundles, pkgutil, Homebrew ----

// ParseInfoPlistXML returns the top-level string values of an XML property
// list (an Info.plist, or the output of "plutil -convert xml1").
func ParseInfoPlistXML(data []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	// Find <plist><dict>.
	depth := 0
	for depth < 2 {
		tok, err := dec.Token()
		if err != nil {
			return nil, errors.New("not an XML property list")
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case depth == 0 && se.Name.Local == "plist":
			depth = 1
		case depth == 1 && se.Name.Local == "dict":
			depth = 2
		default:
			return nil, errors.New("not an XML property list with a dictionary")
		}
	}
	values := map[string]string{}
	key, haveKey := "", false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return values, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return values, nil // </dict>
		case xml.StartElement:
			switch {
			case t.Name.Local == "key":
				var k string
				if err := dec.DecodeElement(&k, &t); err != nil {
					return nil, err
				}
				key, haveKey = k, true
			case t.Name.Local == "string" && haveKey:
				var v string
				if err := dec.DecodeElement(&v, &t); err != nil {
					return nil, err
				}
				values[key] = v
				haveKey = false
			default:
				if err := dec.Skip(); err != nil {
					return nil, err
				}
				haveKey = false
			}
		}
	}
}

// AppItem builds the inventory item of an application bundle from its
// Info.plist values.
func AppItem(bundlePath string, plist map[string]string) protocol.SoftwareItem {
	name := Clean(plist["CFBundleDisplayName"], maxNameBytes)
	if name == "" {
		name = Clean(plist["CFBundleName"], maxNameBytes)
	}
	if name == "" {
		name = Clean(strings.TrimSuffix(filepath.Base(bundlePath), ".app"), maxNameBytes)
	}
	version := Clean(plist["CFBundleShortVersionString"], maxVersionBytes)
	if version == "" {
		version = Clean(plist["CFBundleVersion"], maxVersionBytes)
	}
	return protocol.SoftwareItem{
		Name:    name,
		Version: version,
		Source:  protocol.SourceApp,
		ID:      Clean(plist["CFBundleIdentifier"], maxIDBytes),
	}
}

// ParsePkgutilPkgs parses "pkgutil --pkgs" (one package id per line).
func ParsePkgutilPkgs(out string) []string {
	var ids []string
	for _, l := range Lines(out) {
		l = strings.TrimSpace(l)
		if l == "" || strings.ContainsAny(l, " \t") {
			continue
		}
		ids = append(ids, l)
	}
	return ids
}

// PkgutilInfo is the parsed output of "pkgutil --pkg-info <id>".
type PkgutilInfo struct {
	ID          string
	Version     string
	InstallTime int64
}

// ParsePkgutilInfo parses "pkgutil --pkg-info <id>".
func ParsePkgutilInfo(out string) PkgutilInfo {
	var info PkgutilInfo
	for _, l := range Lines(out) {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "package-id":
			info.ID = v
		case "version":
			info.Version = v
		case "install-time":
			info.InstallTime, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return info
}

// PkgutilItem builds the inventory item of an installer receipt.
func PkgutilItem(id string, info PkgutilInfo) protocol.SoftwareItem {
	return protocol.SoftwareItem{
		Name:        Clean(id, maxNameBytes),
		Version:     Clean(info.Version, maxVersionBytes),
		Source:      protocol.SourcePkgutil,
		ID:          Clean(id, maxIDBytes),
		InstallDate: unixDate(info.InstallTime),
	}
}

// ParseBrewVersions parses "brew list --versions" ("name version [older
// versions...]" per line; the last listed version is the newest).
func ParseBrewVersions(out string) []protocol.SoftwareItem {
	var items []protocol.SoftwareItem
	for _, l := range Lines(out) {
		f := strings.Fields(l)
		if len(f) < 2 || strings.HasPrefix(f[0], "=") || strings.HasSuffix(f[0], ":") {
			continue // "==> Formulae" style headings, warnings
		}
		items = append(items, protocol.SoftwareItem{
			Name:    Clean(f[0], maxNameBytes),
			Version: Clean(f[len(f)-1], maxVersionBytes),
			Source:  protocol.SourceBrew,
			ID:      Clean(f[0], maxIDBytes),
		})
	}
	return items
}

// ---- Linux: dpkg, rpm, snap, flatpak ----

// DpkgQueryFormat is the -f argument of the dpkg-query inventory call.
const DpkgQueryFormat = `${binary:Package}\t${Package}\t${Version}\t${Maintainer}\t${db:Status-Abbrev}\n`

// ParseDpkgQuery parses "dpkg-query -W -f=DpkgQueryFormat". Only packages in
// state "installed" (status abbreviation "ii") are reported.
func ParseDpkgQuery(out string) []protocol.SoftwareItem {
	var items []protocol.SoftwareItem
	for _, l := range Lines(out) {
		f := strings.Split(l, "\t")
		if len(f) < 5 || !strings.HasPrefix(f[4], "ii") {
			continue
		}
		name := Clean(f[1], maxNameBytes)
		if name == "" {
			continue
		}
		items = append(items, protocol.SoftwareItem{
			Name:      name,
			Version:   Clean(f[2], maxVersionBytes),
			Publisher: Clean(f[3], maxPublisherBytes),
			Source:    protocol.SourceDpkg,
			ID:        Clean(f[0], maxIDBytes),
		})
	}
	return items
}

// RpmQueryFormat is the --qf argument of the rpm inventory call.
const RpmQueryFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\n`

func rpmNone(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}

// RpmVersion formats [epoch:]version-release.
func RpmVersion(epoch, version, release string) string {
	v := version
	if release = rpmNone(release); release != "" {
		v += "-" + release
	}
	if epoch = rpmNone(epoch); epoch != "" && epoch != "0" {
		v = epoch + ":" + v
	}
	return v
}

// ParseRpmQa parses "rpm -qa --qf RpmQueryFormat". The gpg-pubkey pseudo
// packages (imported signing keys) are not software and are skipped.
func ParseRpmQa(out string) []protocol.SoftwareItem {
	var items []protocol.SoftwareItem
	for _, l := range Lines(out) {
		f := strings.Split(l, "\t")
		if len(f) < 7 || f[0] == "" || f[0] == "gpg-pubkey" {
			continue
		}
		id := f[0]
		if arch := rpmNone(f[4]); arch != "" {
			id += "." + arch
		}
		installed, _ := strconv.ParseInt(strings.TrimSpace(f[6]), 10, 64)
		items = append(items, protocol.SoftwareItem{
			Name:        Clean(f[0], maxNameBytes),
			Version:     Clean(RpmVersion(f[1], f[2], f[3]), maxVersionBytes),
			Publisher:   Clean(rpmNone(f[5]), maxPublisherBytes),
			Source:      protocol.SourceRPM,
			ID:          Clean(id, maxIDBytes),
			InstallDate: unixDate(installed),
		})
	}
	return items
}

// ParseSnapList parses "snap list" (columns Name Version Rev Tracking
// Publisher Notes, separated by spaces).
func ParseSnapList(out string) []protocol.SoftwareItem {
	var items []protocol.SoftwareItem
	header := true
	for _, l := range Lines(out) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		if header {
			header = false
			if strings.EqualFold(f[0], "Name") {
				continue
			}
		}
		item := protocol.SoftwareItem{
			Name:    Clean(f[0], maxNameBytes),
			Version: Clean(f[1], maxVersionBytes),
			Source:  protocol.SourceSnap,
			ID:      Clean(f[0], maxIDBytes),
		}
		if len(f) >= 5 && f[4] != "-" {
			// Verified publishers carry a marker ("canonical**", "mozilla✓").
			item.Publisher = Clean(strings.TrimRight(f[4], "*✓✪"), maxPublisherBytes)
		}
		items = append(items, item)
	}
	return items
}

// FlatpakColumns is the --columns argument of the flatpak inventory call.
const FlatpakColumns = "name,application,version"

// ParseFlatpakList parses "flatpak list --app --columns=FlatpakColumns"
// (tab-separated when not writing to a terminal).
func ParseFlatpakList(out string) []protocol.SoftwareItem {
	var items []protocol.SoftwareItem
	for _, l := range Lines(out) {
		f := strings.Split(l, "\t")
		if len(f) < 2 {
			continue
		}
		id := Clean(f[1], maxIDBytes)
		name := Clean(f[0], maxNameBytes)
		if id == "" || (strings.EqualFold(name, "Name") && strings.EqualFold(id, "Application ID")) {
			continue
		}
		if name == "" {
			name = id
		}
		item := protocol.SoftwareItem{Name: name, Source: protocol.SourceFlatpak, ID: id}
		if len(f) >= 3 {
			item.Version = Clean(f[2], maxVersionBytes)
		}
		items = append(items, item)
	}
	return items
}
