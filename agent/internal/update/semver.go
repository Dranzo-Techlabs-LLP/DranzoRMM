package update

import (
	"regexp"
	"strconv"
	"strings"
)

// semverRe is Semantic Versioning 2.0.0 with an optional leading "v".
var semverRe = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?` +
	`(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

// maxVersionLen bounds a version string (the same bound the agent core applies).
const maxVersionLen = 64

// version is a parsed semantic version. Build metadata is not kept: it has
// no influence on precedence.
type version struct {
	major, minor, patch uint64
	pre                 []string // pre-release identifiers; empty for a release
}

// parseVersion parses a semantic version ("1.2.3", "v1.2.3-rc.1+build5").
func parseVersion(s string) (version, bool) {
	if len(s) == 0 || len(s) > maxVersionLen {
		return version{}, false
	}
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	var v version
	var err error
	if v.major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return version{}, false
	}
	if v.minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return version{}, false
	}
	if v.patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return version{}, false
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

// ValidVersion reports whether s is a well-formed semantic version.
func ValidVersion(s string) bool {
	_, ok := parseVersion(s)
	return ok
}

func isNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpIdent compares two pre-release identifiers (semver 2.0.0, rule 11.4):
// numeric identifiers compare numerically and rank below alphanumeric ones,
// which compare in ASCII order.
func cmpIdent(a, b string) int {
	an, bn := isNumeric(a), isNumeric(b)
	switch {
	case an && bn:
		// No leading zeros (enforced by the pattern), so a longer number is
		// larger; this never overflows whatever the length.
		if len(a) != len(b) {
			return cmpUint(uint64(len(a)), uint64(len(b)))
		}
		return strings.Compare(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

// compare returns -1, 0 or +1 by semantic-version precedence.
func (v version) compare(o version) int {
	if c := cmpUint(v.major, o.major); c != 0 {
		return c
	}
	if c := cmpUint(v.minor, o.minor); c != 0 {
		return c
	}
	if c := cmpUint(v.patch, o.patch); c != 0 {
		return c
	}
	// A release ranks above any of its pre-releases.
	switch {
	case len(v.pre) == 0 && len(o.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1
	case len(o.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		if c := cmpIdent(v.pre[i], o.pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(v.pre)), uint64(len(o.pre)))
}

// CompareVersions compares two semantic versions by precedence. ok is false
// when either string is not a valid semantic version.
func CompareVersions(a, b string) (cmp int, ok bool) {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	return va.compare(vb), true
}

// SameVersion reports whether two version strings name the same build: equal
// apart from an optional leading "v". Build metadata is significant here
// ("1.0.0+a" and "1.0.0+b" are different builds of equal precedence).
func SameVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}
