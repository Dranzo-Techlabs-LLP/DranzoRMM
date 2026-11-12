package posture

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---- Windows ----

type winPatchReport struct {
	HotFix string `json:"hotfix"`
	WUA    string `json:"wua"`
	Error  string `json:"error"`
}

// ParseWindowsLastPatch turns the output of PSLastPatch into the newest
// installation time (zero when the history is empty).
func ParseWindowsLastPatch(data []byte) (time.Time, error) {
	var r winPatchReport
	if err := json.Unmarshal(data, &r); err != nil {
		return time.Time{}, fmt.Errorf("update history: %w", err)
	}
	var latest time.Time
	for _, s := range []string{r.HotFix, r.WUA} {
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s)); err == nil && t.After(latest) {
			latest = t.UTC()
		}
	}
	if latest.IsZero() && strings.Trim(r.Error, "; ") != "" {
		return time.Time{}, Unsupportedf("the update history is not readable (%s)", OneLine(r.Error, 300))
	}
	return latest, nil
}

// ---- macOS ----

// securityDataPrefixes are display names of background security-data pushes
// in the macOS install history. They arrive every few days and are not
// patches, so they do not count for the last patch date.
var securityDataPrefixes = []string{"XProtect", "MRTConfigData", "Gatekeeper", "MobileAssets", "RosettaUpdateAuto", "TCC", "Core Suggestions", "Incompatible Kernel"}

// softwareUpdateProcesses are the installers that apply Apple software
// updates (App Store and manual package installs are not patches).
var softwareUpdateProcesses = map[string]bool{
	"softwareupdated": true,
	"software update": true,
	"macos installer": true,
	"osinstaller":     true,
}

// ParseInstallHistory reads /Library/Receipts/InstallHistory.plist (XML) and
// returns the time of the newest Apple software update that is not a
// background security-data push (zero when there is none).
func ParseInstallHistory(data []byte) (time.Time, error) {
	v, err := ParsePlist(data)
	if err != nil {
		return time.Time{}, err
	}
	items, ok := v.([]any)
	if !ok {
		return time.Time{}, errors.New("install history: root is not an array")
	}
	var latest time.Time
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		date, ok := m["date"].(time.Time)
		if !ok {
			continue
		}
		proc, _ := m["processName"].(string)
		if !softwareUpdateProcesses[strings.ToLower(strings.TrimSpace(proc))] {
			continue
		}
		name, _ := m["displayName"].(string)
		skip := false
		for _, p := range securityDataPrefixes {
			if strings.HasPrefix(name, p) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if date.After(latest) {
			latest = date
		}
	}
	return latest, nil
}

// ---- Linux ----

// ParseDpkgLog returns the time of the newest package installation or
// upgrade in /var/log/dpkg.log:
//
//	2026-11-10 06:25:13 upgrade libc6:amd64 2.36-9+deb12u8 2.36-9+deb12u9
//	2026-11-10 06:25:14 status installed libc6:amd64 2.36-9+deb12u9
//
// Timestamps are local time (loc).
func ParseDpkgLog(log string, loc *time.Location) (time.Time, bool) {
	if loc == nil {
		loc = time.UTC
	}
	var latest time.Time
	for _, line := range strings.Split(log, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		switch {
		case f[2] == "install", f[2] == "upgrade":
		case f[2] == "status" && f[3] == "installed":
		default:
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", f[0]+" "+f[1], loc)
		if err != nil {
			continue
		}
		if t.After(latest) {
			latest = t
		}
	}
	return latest, !latest.IsZero()
}

// ParseRpmInstallTimes returns the newest time in the output of
// `rpm -qa --queryformat '%{INSTALLTIME}\n'` (Unix seconds, one per line).
func ParseRpmInstallTimes(out string) (time.Time, bool) {
	var latest int64
	for _, line := range strings.Split(out, "\n") {
		n, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		if n > latest {
			latest = n
		}
	}
	if latest == 0 {
		return time.Time{}, false
	}
	return time.Unix(latest, 0).UTC(), true
}
