package patch

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// The Windows Update Agent is driven through its documented COM automation
// API (Microsoft.Update.Session) from Windows PowerShell, which ships with
// every supported Windows version. No third-party module is used.
//
// The scripts are sent to powershell.exe on standard input
// ("-Command -"), so they never appear on a command line. PowerShell reads
// such input like text typed at its prompt: a multi-line statement is only
// run when a blank line follows it, and a blank line inside a statement
// would end it early. Each script is therefore ONE statement "& { ... }"
// without any blank line inside, followed by blank lines (see
// TestWUAScriptsShape). Parameters travel in environment variables, never by
// editing the script text. The scripts print one JSON object on stdout;
// progress goes to stderr.

// PowerShellArgs are the arguments for running a script from stdin.
var PowerShellArgs = []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"}

// Environment variables read by the install script.
const (
	envWUAAll = "DRANZO_WUA_ALL"
	envWUAIDs = "DRANZO_WUA_IDS"
)

// wuaScanScript lists the pending (not installed, not hidden) updates.
const wuaScanScript = `& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'DranzoRMM Agent'
    $searcher = $session.CreateUpdateSearcher()
    $found = $searcher.Search('IsInstalled=0 and IsHidden=0')
    $updates = New-Object System.Collections.ArrayList
    foreach ($u in $found.Updates) {
        $kbs = New-Object System.Collections.ArrayList
        foreach ($k in $u.KBArticleIDs) { [void]$kbs.Add([string]$k) }
        $cats = New-Object System.Collections.ArrayList
        foreach ($c in $u.Categories) { [void]$cats.Add(@{ name = [string]$c.Name; id = [string]$c.CategoryID }) }
        $reboot = 0
        try { $reboot = [int]$u.InstallationBehavior.RebootBehavior } catch { }
        $size = 0
        try { $size = [double]$u.MaxDownloadSize } catch { }
        [void]$updates.Add(@{
            id = [string]$u.Identity.UpdateID
            revision = [int]$u.Identity.RevisionNumber
            title = [string]$u.Title
            kbs = $kbs
            categories = $cats
            msrcSeverity = [string]$u.MsrcSeverity
            maxDownloadSize = $size
            rebootBehavior = $reboot
            type = [int]$u.Type
            isDownloaded = [bool]$u.IsDownloaded
        })
    }
    $pending = $false
    try { $pending = [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch { }
    $last = ''
    try {
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            foreach ($h in $searcher.QueryHistory(0, [Math]::Min($count, 100))) {
                if ($h.Operation -eq 1 -and ($h.ResultCode -eq 2 -or $h.ResultCode -eq 3)) {
                    $last = $h.Date.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    break
                }
            }
        }
    } catch { }
    @{ ok = $true; updates = $updates; rebootRequired = $pending; lastInstallAt = $last } | ConvertTo-Json -Depth 6 -Compress
} catch {
    @{ ok = $false; error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
}


`

// wuaInstallScript downloads and installs the selected updates (by update
// identity) and reports one result per update.
const wuaInstallScript = `& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
function Say([string]$text) { [Console]::Error.WriteLine($text) }
try {
    $all = ($env:DRANZO_WUA_ALL -eq '1')
    $wanted = @{}
    foreach ($i in ([string]$env:DRANZO_WUA_IDS).Split(',')) { if ($i) { $wanted[$i.Trim().ToLowerInvariant()] = $true } }
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'DranzoRMM Agent'
    $searcher = $session.CreateUpdateSearcher()
    Say 'Searching for updates...'
    $found = $searcher.Search('IsInstalled=0 and IsHidden=0')
    $results = New-Object System.Collections.ArrayList
    $selected = New-Object -ComObject Microsoft.Update.UpdateColl
    $seen = @{}
    foreach ($u in $found.Updates) {
        $id = ([string]$u.Identity.UpdateID).ToLowerInvariant()
        if (-not ($all -or $wanted.ContainsKey($id))) { continue }
        $seen[$id] = $true
        if ($u.InstallationBehavior.CanRequestUserInput) {
            [void]$results.Add(@{ id = $id; title = [string]$u.Title; ok = $false; error = 'the update requires user input and cannot be installed unattended'; rebootRequired = $false })
            continue
        }
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        [void]$selected.Add($u)
    }
    foreach ($id in $wanted.Keys) {
        if (-not $seen.ContainsKey($id)) {
            [void]$results.Add(@{ id = $id; title = ''; ok = $false; error = 'the update is not pending on this device (already installed, superseded or hidden)'; rebootRequired = $false })
        }
    }
    $reboot = $false
    if ($selected.Count -gt 0) {
        Say ('Downloading ' + $selected.Count + ' update(s)...')
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $selected
        try { [void]$downloader.Download() } catch { Say ('Download reported: ' + $_.Exception.Message) }
        $ready = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $selected) {
            if ($u.IsDownloaded) { [void]$ready.Add($u) } else {
                [void]$results.Add(@{ id = ([string]$u.Identity.UpdateID).ToLowerInvariant(); title = [string]$u.Title; ok = $false; error = 'the update could not be downloaded'; rebootRequired = $false })
            }
        }
        if ($ready.Count -gt 0) {
            Say ('Installing ' + $ready.Count + ' update(s)...')
            $installer = $session.CreateUpdateInstaller()
            $installer.Updates = $ready
            $outcome = $installer.Install()
            $reboot = [bool]$outcome.RebootRequired
            for ($n = 0; $n -lt $ready.Count; $n++) {
                $u = $ready.Item($n)
                $r = $outcome.GetUpdateResult($n)
                $code = [int]$r.ResultCode
                $ok = ($code -eq 2 -or $code -eq 3)
                $message = ''
                if (-not $ok) { $message = ('installation failed (result code ' + $code + ', HRESULT 0x' + ([int]$r.HResult).ToString('X8') + ')') }
                Say ($(if ($ok) { 'Installed: ' } else { 'Failed: ' }) + [string]$u.Title)
                [void]$results.Add(@{ id = ([string]$u.Identity.UpdateID).ToLowerInvariant(); title = [string]$u.Title; ok = $ok; error = $message; rebootRequired = [bool]$r.RebootRequired })
            }
        }
    }
    try { if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) { $reboot = $true } } catch { }
    @{ ok = $true; results = $results; rebootRequired = $reboot } | ConvertTo-Json -Depth 6 -Compress
} catch {
    @{ ok = $false; error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
}


`

// flexList accepts what the two PowerShell generations emit for a list: a
// JSON array, null, a single bare element, or Windows PowerShell 5.1's
// wrapper object {"value":[...],"Count":n}.
type flexList[T any] []T

func (f *flexList[T]) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" || trimmed == "" {
		*f = nil
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var list []T
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		*f = list
		return nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var wrapper struct {
			Value *json.RawMessage `json:"value"`
			Count *int             `json:"Count"`
		}
		if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Value != nil && wrapper.Count != nil {
			return f.UnmarshalJSON(*wrapper.Value)
		}
	}
	var one T
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*f = []T{one}
	return nil
}

type wuaCategory struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type wuaUpdate struct {
	ID              string                `json:"id"`
	Revision        int                   `json:"revision"`
	Title           string                `json:"title"`
	KBs             flexList[string]      `json:"kbs"`
	Categories      flexList[wuaCategory] `json:"categories"`
	MsrcSeverity    string                `json:"msrcSeverity"`
	MaxDownloadSize float64               `json:"maxDownloadSize"`
	RebootBehavior  int                   `json:"rebootBehavior"`
	Type            int                   `json:"type"`
	IsDownloaded    bool                  `json:"isDownloaded"`
}

type wuaScanDoc struct {
	OK             bool                `json:"ok"`
	Error          string              `json:"error"`
	Updates        flexList[wuaUpdate] `json:"updates"`
	RebootRequired bool                `json:"rebootRequired"`
	LastInstallAt  string              `json:"lastInstallAt"`
}

type wuaInstallResult struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	OK             bool   `json:"ok"`
	Error          string `json:"error"`
	RebootRequired bool   `json:"rebootRequired"`
}

type wuaInstallDoc struct {
	OK             bool                       `json:"ok"`
	Error          string                     `json:"error"`
	Results        flexList[wuaInstallResult] `json:"results"`
	RebootRequired bool                       `json:"rebootRequired"`
}

// jsonObject cuts the JSON object out of a script's stdout (anything a
// profile-less PowerShell might print around it is ignored).
func jsonObject(out string) (string, error) {
	start, end := strings.IndexByte(out, '{'), strings.LastIndexByte(out, '}')
	if start < 0 || end < start {
		return "", errors.New("the Windows Update script printed no result")
	}
	return out[start : end+1], nil
}

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidGUID reports whether s is an update identity (a GUID without braces).
func ValidGUID(s string) bool { return guidRe.MatchString(s) }

// Windows Update classification ids (stable across display languages).
var wuaCategoryIDs = map[string]string{
	"0fa1201d-4330-4fa8-8ae9-b877473b6441": CategorySecurity,
	"e6cf1350-c01b-414d-a61f-263d14d133b4": CategoryCritical,
	"e0789628-ce08-4437-be74-2495b842f43b": CategoryDefinition,
	"ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0": CategoryDriver,
	"b54e7d24-7add-428f-8b75-90a396fa584f": CategoryFeature,
	"3689bdc8-b205-4af4-8d4a-a63924c5e9d5": CategoryFeature, // Upgrades
	"28bc880e-0592-4cbf-8f95-c79b17911d5f": CategoryRollup,
	"68c5b0a3-d1a6-4553-ae49-01d3a7827828": CategoryServicePack,
	"b4832bd8-e735-4761-8daf-37f882276dab": CategoryTool,
	"cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83": CategoryUpdate,
}

// English classification names, used when an id is not known.
var wuaCategoryNames = map[string]string{
	"security updates":   CategorySecurity,
	"critical updates":   CategoryCritical,
	"definition updates": CategoryDefinition,
	"drivers":            CategoryDriver,
	"feature packs":      CategoryFeature,
	"upgrades":           CategoryFeature,
	"update rollups":     CategoryRollup,
	"service packs":      CategoryServicePack,
	"tools":              CategoryTool,
	"updates":            CategoryUpdate,
}

// The most significant classification wins when an update has several.
var categoryRank = map[string]int{
	CategoryUpdate: 1, CategoryTool: 2, CategoryFeature: 3, CategoryDriver: 4, CategoryServicePack: 5,
	CategoryRollup: 6, CategoryDefinition: 7, CategoryCritical: 8, CategorySecurity: 9,
}

func wuaCategoryOf(u wuaUpdate) string {
	best := ""
	consider := func(c string) {
		if c != "" && categoryRank[c] > categoryRank[best] {
			best = c
		}
	}
	for _, c := range u.Categories {
		if mapped, ok := wuaCategoryIDs[strings.ToLower(strings.Trim(c.ID, "{}"))]; ok {
			consider(mapped)
		} else {
			consider(wuaCategoryNames[strings.ToLower(strings.TrimSpace(c.Name))])
		}
	}
	if best == "" {
		if u.Type == 2 { // UpdateType.utDriver
			return CategoryDriver
		}
		return CategoryUpdate
	}
	return best
}

// WUAScan is the parsed result of the scan script.
type WUAScan struct {
	Pending        []protocol.PendingPatch
	RebootRequired bool
	LastInstallAt  *time.Time
}

// ParseWUAScan parses the JSON printed by the scan script.
func ParseWUAScan(stdout string) (WUAScan, error) {
	obj, err := jsonObject(stdout)
	if err != nil {
		return WUAScan{}, err
	}
	var doc wuaScanDoc
	if err := json.Unmarshal([]byte(obj), &doc); err != nil {
		return WUAScan{}, fmt.Errorf("invalid result from the Windows Update script: %w", err)
	}
	if !doc.OK {
		return WUAScan{}, fmt.Errorf("search for Windows updates failed: %s", software.Clean(doc.Error, 500))
	}
	scan := WUAScan{RebootRequired: doc.RebootRequired}
	if t, err := time.Parse("2006-01-02T15:04:05Z", doc.LastInstallAt); err == nil {
		scan.LastInstallAt = &t
	}
	for _, u := range doc.Updates {
		if !ValidGUID(u.ID) {
			continue
		}
		id, ok := EncodeID(SourceWUA, strings.ToLower(u.ID))
		if !ok {
			continue
		}
		p := protocol.PendingPatch{
			ID:       id,
			Title:    software.Clean(u.Title, 256),
			Category: wuaCategoryOf(u),
			Severity: normalizeSeverity(u.MsrcSeverity),
			Source:   SourceWUA,
		}
		if len(u.KBs) > 0 && u.KBs[0] != "" {
			p.KB = software.Clean("KB"+strings.TrimPrefix(strings.ToUpper(u.KBs[0]), "KB"), 32)
		}
		if u.MaxDownloadSize > 0 && u.MaxDownloadSize < 1<<50 {
			size := int64(u.MaxDownloadSize)
			p.SizeBytes = &size
		}
		// InstallationRebootBehavior: 0 never, 1 always, 2 can request.
		switch u.RebootBehavior {
		case 0:
			no := false
			p.RequiresReboot = &no
		case 1:
			yes := true
			p.RequiresReboot = &yes
		}
		scan.Pending = append(scan.Pending, p)
	}
	return scan, nil
}

// WUAInstall is the parsed result of the install script.
type WUAInstall struct {
	Items          []protocol.PatchInstallItem
	RebootRequired bool
}

// ParseWUAInstall parses the JSON printed by the install script.
func ParseWUAInstall(stdout string) (WUAInstall, error) {
	obj, err := jsonObject(stdout)
	if err != nil {
		return WUAInstall{}, err
	}
	var doc wuaInstallDoc
	if err := json.Unmarshal([]byte(obj), &doc); err != nil {
		return WUAInstall{}, fmt.Errorf("invalid result from the Windows Update script: %w", err)
	}
	if !doc.OK {
		return WUAInstall{}, fmt.Errorf("installation of Windows updates failed: %s", software.Clean(doc.Error, 500))
	}
	res := WUAInstall{RebootRequired: doc.RebootRequired}
	for _, r := range doc.Results {
		if !ValidGUID(r.ID) {
			continue
		}
		id, ok := EncodeID(SourceWUA, strings.ToLower(r.ID))
		if !ok {
			continue
		}
		item := protocol.PatchInstallItem{ID: id, OK: r.OK}
		if !r.OK {
			item.Error = software.Clean(r.Error, 300)
			if item.Error == "" {
				item.Error = "installation failed"
			}
		}
		res.RebootRequired = res.RebootRequired || r.RebootRequired
		res.Items = append(res.Items, item)
	}
	return res, nil
}
