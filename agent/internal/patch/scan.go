package patch

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// ReporterName is the name of the patch.state reporter.
const ReporterName = "patch.state"

// Report limits.
const (
	// collectTimeout bounds one whole patch scan.
	collectTimeout = 30 * time.Minute
	// MaxPending bounds the number of reported updates.
	MaxPending = 2000
	// maxScanErrorBytes bounds the scanError text.
	maxScanErrorBytes = 1024
)

// Scanner builds patch.state reports from the update sources of this OS.
type Scanner struct {
	plat      platform.Platform
	providers []Provider
	now       func() time.Time
	// Refresh updates each source's index from the network before listing
	// (apt-get update, dnf --refresh, brew update).
	Refresh bool
}

// NewScanner returns the scanner for the OS this binary was built for.
func NewScanner(plat platform.Platform) *Scanner {
	return &Scanner{plat: plat, providers: osProviders(plat), now: time.Now, Refresh: true}
}

// NewScannerWith returns a scanner over explicit providers (tests).
func NewScannerWith(plat platform.Platform, providers ...Provider) *Scanner {
	return &Scanner{plat: plat, providers: providers, now: time.Now, Refresh: true}
}

// Providers returns the update sources of this OS.
func (s *Scanner) Providers() []Provider { return s.providers }

// Provider returns the provider of a source (nil if this OS has none).
func (s *Scanner) Provider(source string) Provider {
	for _, p := range s.providers {
		if p.Source() == source {
			return p
		}
	}
	return nil
}

// Collect scans every usable source. It never fails: a source that cannot
// be used is listed in Unsupported, a failed scan is described in ScanError.
func (s *Scanner) Collect(ctx context.Context) *protocol.PatchState {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	state := &protocol.PatchState{Pending: []protocol.PendingPatch{}, Unsupported: []string{}}
	var problems, absentOptional []string
	usable := 0
	for _, p := range s.providers {
		if err := p.Check(ctx); err != nil {
			switch {
			case errors.Is(err, errAbsent) && p.Optional():
				absentOptional = append(absentOptional, p.Source())
			default:
				state.Unsupported = append(state.Unsupported, p.Source())
			}
			continue
		}
		usable++
		res, err := p.Scan(ctx, s.Refresh)
		if err != nil {
			problems = append(problems, p.Source()+": "+err.Error())
			continue
		}
		if res.Warning != "" {
			problems = append(problems, p.Source()+": "+res.Warning)
		}
		state.Pending = append(state.Pending, res.Pending...)
		state.RebootRequired = state.RebootRequired || res.RebootRequired
		if res.LastInstallAt != nil && (state.LastInstallAt == nil || res.LastInstallAt.After(*state.LastInstallAt)) {
			t := res.LastInstallAt.UTC()
			state.LastInstallAt = &t
		}
	}
	if usable == 0 {
		// Not even one source: the optional ones are then missing for real
		// (for example a Linux system with neither apt nor dnf).
		state.Unsupported = append(state.Unsupported, absentOptional...)
	}
	if s.plat != nil {
		if pending, err := s.plat.PendingReboot(ctx); err == nil && pending {
			state.RebootRequired = true
		}
	}
	state.Pending = normalizePending(state.Pending)
	sort.Strings(state.Unsupported)
	state.ScanError = software.Clean(strings.Join(problems, "; "), maxScanErrorBytes)
	state.CollectedAt = s.now().UTC()
	return state
}

// normalizePending drops entries without a valid id, de-duplicates, sorts
// (source, then title, then id) and caps the list.
func normalizePending(in []protocol.PendingPatch) []protocol.PendingPatch {
	seen := make(map[string]bool, len(in))
	out := make([]protocol.PendingPatch, 0, len(in))
	for _, p := range in {
		if !protocol.ValidPackageID(p.ID) || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		if p.Title == "" {
			p.Title = p.ID
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if x, y := strings.ToLower(a.Title), strings.ToLower(b.Title); x != y {
			return x < y
		}
		return a.ID < b.ID
	})
	if len(out) > MaxPending {
		out = out[:MaxPending]
	}
	return out
}
