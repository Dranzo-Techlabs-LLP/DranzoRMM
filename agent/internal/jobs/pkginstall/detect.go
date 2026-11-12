package pkginstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// Detection types (PROTOCOL.md section 6.2).
const (
	DetectFile     = "file"
	DetectRegistry = "registry"
	DetectPkgutil  = "pkgutil"
	DetectDpkg     = "dpkg"
	DetectRpm      = "rpm"
	DetectWinget   = "winget"
	DetectBrew     = "brew"
	DetectApp      = "app"
)

// Limits of a detection rule.
const (
	maxDetectionKeyBytes = 1024
	maxValueNameBytes    = 255
)

var minVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:~-]{0,63}$`)

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// validPackageKey applies the packageId rule to a detection key that is
// handed to a package manager.
func validPackageKey(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && protocol.ValidPackageID(s)
}

// splitRegistryKey accepts "HKLM\path" or "HKEY_LOCAL_MACHINE\path" and
// returns the path below HKLM. Only the machine hive is meaningful for a
// service (HKCU would be the service account's own hive).
func splitRegistryKey(key string) (string, bool) {
	root, sub, ok := strings.Cut(key, `\`)
	if !ok {
		return "", false
	}
	switch strings.ToUpper(root) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
	default:
		return "", false
	}
	if sub == "" || strings.HasPrefix(sub, `\`) || strings.HasSuffix(sub, `\`) || strings.Contains(sub, `\\`) || strings.Contains(sub, "/") {
		return "", false
	}
	return sub, true
}

// ValidateDetection checks every field of a detection rule. Whether the
// rule's type exists on this operating system is decided later (Env.Detect).
func ValidateDetection(d *protocol.Detection) error {
	if d.Key == "" || len(d.Key) > maxDetectionKeyBytes || hasControl(d.Key) {
		return errors.New("detection.key is empty, too long or contains control characters")
	}
	if len(d.ValueName) > maxValueNameBytes || hasControl(d.ValueName) {
		return errors.New("detection.valueName is too long or contains control characters")
	}
	if d.MinVersion != "" && !minVersionRe.MatchString(d.MinVersion) {
		return errors.New("detection.minVersion is not a valid version string")
	}
	switch d.Type {
	case DetectFile:
		if !filepath.IsAbs(d.Key) {
			return errors.New("detection.key must be an absolute path for type file")
		}
	case DetectRegistry:
		if _, ok := splitRegistryKey(d.Key); !ok {
			return errors.New(`detection.key must be a key below HKLM\ for type registry`)
		}
	case DetectPkgutil, DetectDpkg, DetectRpm, DetectWinget, DetectBrew:
		if !validPackageKey(d.Key) {
			return fmt.Errorf("detection.key is not a valid package identifier for type %s", d.Type)
		}
	case DetectApp:
		if filepath.IsAbs(d.Key) {
			if !strings.HasSuffix(strings.ToLower(d.Key), ".app") {
				return errors.New("detection.key must end in .app when it is a path")
			}
		} else if strings.ContainsAny(d.Key, `/\:`) || strings.HasPrefix(d.Key, ".") || len(d.Key) > 255 {
			return errors.New("detection.key must be an application name or an absolute path to a .app bundle")
		}
	default:
		return errors.New("detection.type must be one of file, registry, pkgutil, dpkg, rpm, winget, brew, app")
	}
	return nil
}

// unsupportedError marks something this operating system cannot do.
type unsupportedError struct{ what string }

func (e *unsupportedError) Error() string { return e.what }

func unsupportedf(format string, args ...any) error {
	return &unsupportedError{what: fmt.Sprintf(format, args...)}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Detect evaluates a validated detection rule. It returns an
// *unsupportedError when the rule's type does not exist on this OS.
func (e *Env) Detect(ctx context.Context, r software.Runner, d *protocol.Detection) (software.PackageState, error) {
	if !contains(e.Detections, d.Type) {
		return software.PackageState{}, unsupportedf("detection type %s is not available on %s", d.Type, e.OSName)
	}
	state, err := e.detect(ctx, r, d)
	if errors.Is(err, software.ErrToolMissing) {
		return state, unsupportedf("detection type %s: %v", d.Type, err)
	}
	return state, err
}

func (e *Env) detect(ctx context.Context, r software.Runner, d *protocol.Detection) (software.PackageState, error) {
	switch d.Type {
	case DetectFile:
		if _, err := os.Stat(d.Key); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return software.PackageState{}, nil
			}
			return software.PackageState{}, err
		}
		state := software.PackageState{Installed: true}
		if e.FileVersion != nil {
			state.Version = e.FileVersion(d.Key)
		}
		return state, nil
	case DetectRegistry:
		if e.Registry == nil {
			return software.PackageState{}, unsupportedf("detection type registry is not available on %s", e.OSName)
		}
		sub, _ := splitRegistryKey(d.Key)
		return e.Registry(sub, d.ValueName)
	case DetectPkgutil:
		return software.QueryPkgutil(ctx, r, e.Lookup("pkgutil"), d.Key)
	case DetectDpkg:
		return software.QueryDpkg(ctx, r, e.Lookup("dpkg-query"), d.Key)
	case DetectRpm:
		return software.QueryRpm(ctx, r, e.Lookup("rpm"), d.Key)
	case DetectWinget:
		return software.QueryWinget(ctx, r, e.Lookup("winget"), d.Key)
	case DetectBrew:
		if !e.Brew.Installed() {
			return software.PackageState{}, fmt.Errorf("brew: %w", software.ErrToolMissing)
		}
		return e.Brew.Query(ctx, d.Key)
	case DetectApp:
		return e.detectApp(ctx, r, d.Key)
	}
	return software.PackageState{}, unsupportedf("detection type %s", d.Type)
}

// detectApp looks for an application bundle: an absolute path, or a name
// searched in the application folders (".app" is appended when missing).
func (e *Env) detectApp(ctx context.Context, r software.Runner, key string) (software.PackageState, error) {
	var candidates []string
	if filepath.IsAbs(key) {
		candidates = []string{filepath.Clean(key)}
	} else {
		name := key
		if !strings.HasSuffix(strings.ToLower(name), ".app") {
			name += ".app"
		}
		for _, dir := range e.AppDirs {
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}
	for _, bundle := range candidates {
		fi, err := os.Stat(bundle)
		if err != nil || !fi.IsDir() {
			continue
		}
		state := software.PackageState{Installed: true}
		if plist, err := software.ReadInfoPlist(ctx, r, e.Lookup("plutil"), filepath.Join(bundle, "Contents", "Info.plist")); err == nil {
			state.Version = software.AppItem(bundle, plist).Version
		}
		return state, nil
	}
	return software.PackageState{}, nil
}

// Satisfied reports whether the detected state fulfils the rule: installed
// and, when a minimum version is given, at a known version that is not older.
func Satisfied(state software.PackageState, minVersion string) bool {
	if !state.Installed {
		return false
	}
	if minVersion == "" {
		return true
	}
	return state.Version != "" && software.CompareVersions(state.Version, minVersion) >= 0
}
