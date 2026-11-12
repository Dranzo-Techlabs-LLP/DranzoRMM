package software

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// queryTimeout bounds a single "is this package installed" query.
const queryTimeout = 2 * time.Minute

// ErrToolMissing reports that the tool needed for a query is not installed.
var ErrToolMissing = errors.New("required tool is not installed")

// PackageState is the answer to "is it installed, which version".
type PackageState struct {
	Installed bool
	Version   string
}

// The package-name rules below are stricter than the protocol's general
// packageId pattern. That pattern also matches URLs and relative paths
// ("https://host/x.rpm", "dir/x.deb"), which dnf, apt and Homebrew would
// treat as "install this file" instead of "install this package from the
// configured repositories". A package manager job must never become a way
// to install an arbitrary file: that is what package.install, with its
// SHA-256 verification, is for.
var (
	aptNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9-]{1,32})?$`)
	rpmNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,199}$`)
)

// ValidAptName reports whether s is a Debian package name, optionally with
// an architecture qualifier ("libc6:arm64").
func ValidAptName(s string) bool { return aptNameRe.MatchString(s) }

// ValidRpmName reports whether s is an RPM package name, optionally with an
// architecture suffix ("bash.x86_64"). Local package files are refused.
func ValidRpmName(s string) bool {
	return rpmNameRe.MatchString(s) && !strings.HasSuffix(strings.ToLower(s), ".rpm")
}

// ValidBrewName reports whether s is a formula or cask token, optionally
// tap-qualified ("homebrew/cask/firefox") or versioned ("node@20"). URLs,
// formula files and path traversal are refused.
func ValidBrewName(s string) bool {
	if s == "" || len(s) > 200 || strings.HasPrefix(s, "-") || !protocol.ValidPackageID(s) {
		return false
	}
	lower := strings.ToLower(s)
	return !strings.Contains(s, ":") && !strings.Contains(s, "..") && !strings.Contains(s, "//") &&
		!strings.HasSuffix(lower, ".rb") && !strings.HasSuffix(s, "/") && strings.Count(s, "/") <= 2
}

// ValidWingetID reports whether s is a winget package identifier
// ("Publisher.Package", or a Microsoft Store product id).
func ValidWingetID(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && protocol.ValidPackageID(s) && !strings.ContainsAny(s, "/:@")
}

// ParseDpkgStatus parses the output of
// dpkg-query -W -f='${db:Status-Abbrev}\t${Version}\n' -- <package>.
func ParseDpkgStatus(out string) PackageState {
	for _, l := range Lines(out) {
		status, version, ok := strings.Cut(l, "\t")
		if ok && strings.HasPrefix(status, "ii") {
			return PackageState{Installed: true, Version: Clean(version, maxVersionBytes)}
		}
	}
	return PackageState{}
}

// QueryDpkg asks dpkg whether a package is installed.
func QueryDpkg(ctx context.Context, r Runner, dpkgQuery, id string) (PackageState, error) {
	if dpkgQuery == "" {
		return PackageState{}, fmt.Errorf("dpkg-query: %w", ErrToolMissing)
	}
	res, err := Output(ctx, r, queryTimeout, platform.Command{
		Path: dpkgQuery,
		Args: []string{"-W", `-f=${db:Status-Abbrev}\t${Version}\n`, "--", id},
	})
	if err != nil {
		return PackageState{}, err
	}
	// Exit code 1 means "no packages found".
	return ParseDpkgStatus(res.Stdout), nil
}

// ParseRpmQuery parses the output of
// rpm -q --qf '%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n' -- <package>.
func ParseRpmQuery(out string) PackageState {
	best := PackageState{}
	for _, l := range Lines(out) {
		f := strings.Split(l, "\t")
		if len(f) != 3 {
			continue // "package foo is not installed"
		}
		v := Clean(RpmVersion(f[0], f[1], f[2]), maxVersionBytes)
		// Several versions can be installed side by side (kernels): report the newest.
		if !best.Installed || CompareVersions(v, best.Version) > 0 {
			best = PackageState{Installed: true, Version: v}
		}
	}
	return best
}

// QueryRpm asks rpm whether a package is installed.
func QueryRpm(ctx context.Context, r Runner, rpm, id string) (PackageState, error) {
	if rpm == "" {
		return PackageState{}, fmt.Errorf("rpm: %w", ErrToolMissing)
	}
	res, err := Output(ctx, r, queryTimeout, platform.Command{
		Path: rpm,
		Args: []string{"-q", "--qf", `%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n`, "--", id},
	})
	if err != nil {
		return PackageState{}, err
	}
	if res.ExitCode != 0 {
		return PackageState{}, nil
	}
	return ParseRpmQuery(res.Stdout), nil
}

// WingetListArgs are the arguments of the exact-id winget query.
func WingetListArgs(id string) []string {
	return []string{"list", "-e", "--id", id, "--accept-source-agreements", "--disable-interactivity"}
}

// ParseWingetQuery finds id in the table printed by "winget list -e --id".
func ParseWingetQuery(out, id string) PackageState {
	for _, row := range ParseWingetTable(out) {
		if strings.EqualFold(row.ID, id) {
			return PackageState{Installed: true, Version: Clean(row.Version, maxVersionBytes)}
		}
	}
	return PackageState{}
}

// QueryWinget asks winget whether a package is installed.
func QueryWinget(ctx context.Context, r Runner, winget, id string) (PackageState, error) {
	if winget == "" {
		return PackageState{}, fmt.Errorf("winget: %w", ErrToolMissing)
	}
	res, err := Output(ctx, r, queryTimeout, platform.Command{Path: winget, Args: WingetListArgs(id)})
	if err != nil {
		return PackageState{}, err
	}
	// winget exits non-zero with "No installed package found" when absent.
	return ParseWingetQuery(res.Stdout, id), nil
}

// QueryPkgutil asks pkgutil whether an installer receipt exists.
func QueryPkgutil(ctx context.Context, r Runner, pkgutil, id string) (PackageState, error) {
	if pkgutil == "" {
		return PackageState{}, fmt.Errorf("pkgutil: %w", ErrToolMissing)
	}
	res, err := Output(ctx, r, queryTimeout, platform.Command{Path: pkgutil, Args: []string{"--pkg-info", id}})
	if err != nil {
		return PackageState{}, err
	}
	if res.ExitCode != 0 {
		return PackageState{}, nil
	}
	info := ParsePkgutilInfo(res.Stdout)
	if info.ID == "" {
		return PackageState{}, nil
	}
	return PackageState{Installed: true, Version: Clean(info.Version, maxVersionBytes)}, nil
}

// ParseBrewQuery parses "brew list --versions -- <name>".
func ParseBrewQuery(out string) PackageState {
	items := ParseBrewVersions(out)
	if len(items) == 0 {
		return PackageState{}
	}
	return PackageState{Installed: true, Version: items[0].Version}
}
