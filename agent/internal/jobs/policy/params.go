package policy

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Parameter limits.
const (
	// MaxAllowedAdmins bounds params.allowed of localadmins.allowed.
	MaxAllowedAdmins = 256
	// MaxAccountNameBytes bounds one account name.
	MaxAccountNameBytes = 256
	// Screen lock timeout range (seconds).
	MinScreenLockSeconds = 1
	MaxScreenLockSeconds = 86400
	// Password policy ranges ("net accounts" accepts 0-14 and 1-999).
	MinPasswordLength = 1
	MaxPasswordLength = 14
	MinPasswordAge    = 1
	MaxPasswordAge    = 999
)

// accountRe is the shape of an account name: an optional "DOMAIN\" part and
// a name, each starting with a letter, digit or underscore and continuing
// with letters, digits and "_ . - @" or inner spaces, optionally ending in
// "$" (machine and managed service accounts). No shell metacharacter, path
// separator or leading "-" (which a tool could read as an option) can pass.
var accountRe = regexp.MustCompile(`^(?:[\p{L}\p{N}_][\p{L}\p{N}_.@ -]{0,127}\$?\\)?[\p{L}\p{N}_][\p{L}\p{N}_.@ -]{0,127}\$?$`)

// ValidAccountName reports whether s is acceptable as an account name.
func ValidAccountName(s string) bool {
	if s == "" || len(s) > MaxAccountNameBytes || !utf8.ValidString(s) {
		return false
	}
	if strings.TrimSpace(s) != s || strings.Contains(s, "  ") || strings.Contains(s, ` \`) || strings.Contains(s, `\ `) {
		return false
	}
	return accountRe.MatchString(s)
}

// intParam reads an integer parameter. JSON numbers arrive as float64; a
// value with a fraction, a string or anything outside [lo, hi] is refused.
func intParam(params map[string]any, key string, lo, hi int) (value int, present bool, err error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return 0, false, nil
	}
	f, ok := raw.(float64)
	if !ok {
		return 0, true, fmt.Errorf("%s must be a number", key)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, true, fmt.Errorf("%s must be a whole number", key)
	}
	if f < float64(lo) || f > float64(hi) {
		return 0, true, fmt.Errorf("%s must be between %d and %d", key, lo, hi)
	}
	return int(f), true, nil
}

// boolParam reads a boolean parameter.
func boolParam(params map[string]any, key string) (value, present bool, err error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return false, false, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, true, fmt.Errorf("%s must be true or false", key)
	}
	return b, true, nil
}

// stringParam reads a string parameter of at most limit bytes.
func stringParam(params map[string]any, key string, limit int) (value string, present bool, err error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", false, nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", true, fmt.Errorf("%s must be a string", key)
	}
	if len(s) > limit {
		return "", true, fmt.Errorf("%s exceeds %d bytes", key, limit)
	}
	return s, true, nil
}

// accountListParam reads a list of account names. The error never echoes a
// rejected name (it could be an injection attempt meant for a log viewer).
func accountListParam(params map[string]any, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, fmt.Errorf("%s is required (a list of account names; it may be empty)", key)
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of account names", key)
	}
	if len(list) > MaxAllowedAdmins {
		return nil, fmt.Errorf("%s has more than %d entries", key, MaxAllowedAdmins)
	}
	names := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", key, i)
		}
		if !ValidAccountName(s) {
			return nil, fmt.Errorf("%s[%d] is not a valid account name", key, i)
		}
		names = append(names, s)
	}
	return names, nil
}
