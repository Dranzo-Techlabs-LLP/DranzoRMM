package software

import "strings"

// versionTokens splits a version into runs of digits and runs of letters;
// every other character is a separator.
func versionTokens(v string) []string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	var tokens []string
	start, kind := -1, 0 // kind: 1 digits, 2 letters
	flush := func(end int) {
		if start >= 0 {
			tokens = append(tokens, v[start:end])
			start = -1
		}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		k := 0
		switch {
		case c >= '0' && c <= '9':
			k = 1
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			k = 2
		}
		if k == 0 || k != kind {
			flush(i)
		}
		if k != 0 && start < 0 {
			start = i
		}
		kind = k
	}
	flush(len(v))
	return tokens
}

func isNumeric(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// CompareVersions compares two version strings segment by segment: numeric
// segments numerically (of any length), alphabetic ones case-insensitively,
// and a numeric segment is newer than an alphabetic one. Missing trailing
// numeric segments count as zero ("1.2" equals "1.2.0"). It returns -1, 0 or
// 1. This is the generic ordering used for detection rules (minVersion); it
// does not implement the special pre-release rules of any one packaging
// system.
func CompareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			if isNumeric(tb[i]) && strings.Trim(tb[i], "0") == "" {
				continue
			}
			return -1
		case i >= len(tb):
			if isNumeric(ta[i]) && strings.Trim(ta[i], "0") == "" {
				continue
			}
			return 1
		}
		x, y := ta[i], tb[i]
		nx, ny := isNumeric(x), isNumeric(y)
		var c int
		switch {
		case nx && ny:
			c = compareNumeric(x, y)
		case nx:
			c = 1
		case ny:
			c = -1
		default:
			c = strings.Compare(strings.ToLower(x), strings.ToLower(y))
		}
		if c != 0 {
			return c
		}
	}
	return 0
}
