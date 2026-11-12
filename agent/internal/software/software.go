package software

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// ReporterName is the name of the software.inventory reporter.
const ReporterName = "software.inventory"

// Collection limits.
const (
	// collectTimeout bounds one whole inventory collection.
	collectTimeout = 5 * time.Minute
	// maxPayloadBytes keeps the report well below the 2 MiB message limit
	// even when every field is at its maximum length.
	maxPayloadBytes = 1536 << 10
	// itemOverheadBytes approximates the JSON syntax around one item.
	itemOverheadBytes = 96
	// maxAppBundles bounds the application bundle scan.
	maxAppBundles = 2000
)

// Gatherer collects the raw items of one operating system and names the
// sources that exist on it but could not be read.
type Gatherer func(ctx context.Context, plat platform.Platform) (items []protocol.SoftwareItem, unsupported []string)

// Collector builds software.inventory reports.
type Collector struct {
	plat   platform.Platform
	gather Gatherer
	now    func() time.Time
}

// NewCollector returns the collector for the OS this binary was built for.
func NewCollector(plat platform.Platform) *Collector {
	return &Collector{plat: plat, gather: gatherOS, now: time.Now}
}

// NewCollectorWith returns a collector with a custom gatherer (tests).
func NewCollectorWith(plat platform.Platform, g Gatherer) *Collector {
	return &Collector{plat: plat, gather: g, now: time.Now}
}

// Collect gathers the inventory. It never fails: sources that cannot be read
// are listed in Unsupported.
func (c *Collector) Collect(ctx context.Context) *protocol.SoftwareInventory {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	raw, unsupported := c.gather(ctx, c.plat)
	items, truncated := Normalize(raw)
	if unsupported == nil {
		unsupported = []string{}
	}
	sort.Strings(unsupported)
	return &protocol.SoftwareInventory{
		CollectedAt: c.now().UTC(),
		Items:       items,
		Truncated:   truncated,
		Unsupported: unsupported,
	}
}

func itemBytes(it protocol.SoftwareItem) int {
	return itemOverheadBytes + len(it.Name) + len(it.Version) + len(it.Publisher) + len(it.Source) + len(it.ID) + len(it.InstallDate)
}

// Normalize cleans, de-duplicates and sorts the items (by name, then
// version, source and id; stable across runs) and caps the list at
// protocol.MaxSoftwareItems and at the payload size budget. truncated
// reports whether anything was cut.
func Normalize(raw []protocol.SoftwareItem) (items []protocol.SoftwareItem, truncated bool) {
	type key struct{ source, id, name, version string }
	seen := make(map[key]struct{}, len(raw))
	items = make([]protocol.SoftwareItem, 0, len(raw))
	for _, it := range raw {
		it.Name = Clean(it.Name, maxNameBytes)
		it.Version = Clean(it.Version, maxVersionBytes)
		it.Publisher = Clean(it.Publisher, maxPublisherBytes)
		it.ID = Clean(it.ID, maxIDBytes)
		it.InstallDate = Clean(it.InstallDate, 32)
		if it.Name == "" || it.Source == "" {
			continue
		}
		// An item with an id is identified by it; otherwise by its name.
		k := key{source: it.Source, id: strings.ToLower(it.ID), version: it.Version}
		if it.ID == "" {
			k.name = strings.ToLower(it.Name)
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		items = append(items, it)
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if x, y := strings.ToLower(a.Name), strings.ToLower(b.Name); x != y {
			return x < y
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.ID < b.ID
	})
	if len(items) > protocol.MaxSoftwareItems {
		items = items[:protocol.MaxSoftwareItems]
		truncated = true
	}
	total := 0
	for i, it := range items {
		total += itemBytes(it)
		if total > maxPayloadBytes {
			items = items[:i]
			truncated = true
			break
		}
	}
	return items, truncated
}

// ---- application bundles (macOS; filesystem logic is OS-independent) ----

// maxInfoPlistBytes bounds an Info.plist read.
const maxInfoPlistBytes = 1 << 20

// ErrBinaryPlist is returned by ReadInfoPlist when a binary property list
// cannot be converted because plutil is not available.
var ErrBinaryPlist = errors.New("binary property list and no plutil to convert it")

// ReadInfoPlist returns the top-level string values of a property list file.
// XML property lists are parsed directly; binary ones are converted with
// "plutil -convert xml1 -o - <file>" first (plutil is the path of that tool,
// "" if unavailable).
func ReadInfoPlist(ctx context.Context, r Runner, plutil, path string) (map[string]string, error) {
	data, err := fsutil.ReadFileLimited(path, maxInfoPlistBytes)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(data, []byte("bplist")) {
		if plutil == "" {
			return nil, ErrBinaryPlist
		}
		res, err := Output(ctx, r, 15*time.Second, platform.Command{Path: plutil, Args: []string{"-convert", "xml1", "-o", "-", path}})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, errors.New("plutil could not convert the property list")
		}
		data = []byte(res.Stdout)
	}
	return ParseInfoPlistXML(data)
}

// FindAppBundles lists the *.app bundles in dirs, looking at most one folder
// level deeper (for example /Applications/Utilities/Terminal.app). Symbolic
// links are not followed.
func FindAppBundles(dirs []string) []string {
	var bundles []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if len(bundles) >= maxAppBundles {
				return
			}
			name := e.Name()
			if !e.IsDir() || strings.HasPrefix(name, ".") {
				continue
			}
			full := filepath.Join(dir, name)
			if strings.HasSuffix(strings.ToLower(name), ".app") {
				bundles = append(bundles, full)
			} else if depth < 1 {
				walk(full, depth+1)
			}
		}
	}
	for _, d := range dirs {
		walk(d, 0)
	}
	sort.Strings(bundles)
	return bundles
}

// AppItems reads the Info.plist of every bundle. A bundle whose Info.plist
// cannot be read is still reported, by its file name and without a version.
func AppItems(ctx context.Context, r Runner, plutil string, bundles []string) []protocol.SoftwareItem {
	items := make([]protocol.SoftwareItem, 0, len(bundles))
	for _, b := range bundles {
		if ctx.Err() != nil {
			break
		}
		plist, err := ReadInfoPlist(ctx, r, plutil, filepath.Join(b, "Contents", "Info.plist"))
		if err != nil {
			plist = nil
		}
		items = append(items, AppItem(b, plist))
	}
	return items
}
