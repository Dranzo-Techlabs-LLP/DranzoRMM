package update

import (
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.10.0", "1.9.0", 1},     // numeric, not lexical
		{"0.2.0", "0.1.0-dev", 1},  // the development default
		{"0.1.0", "0.1.0-dev", 1},  // a release ranks above its pre-releases
		{"0.1.0-dev", "0.1.0", -1}, //
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1}, // numeric below alphanumeric
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1}, // numeric identifiers compare numerically
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0-rc.1", "1.0.0-rc.1", 0},
		{"1.0.0+build.1", "1.0.0+build.2", 0}, // build metadata has no precedence
		{"1.0.0-rc.1+a", "1.0.0-rc.1+b", 0},
		{"1.0.0-99999999999999999999999", "1.0.0-100000000000000000000000", -1}, // no overflow
		{"1.0.0-a-b", "1.0.0-a", 1},
		{"18446744073709551615.0.0", "1.0.0", 1},
	}
	for _, c := range cases {
		got, ok := CompareVersions(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d", c.a, c.b, got, ok, c.want)
		}
		// Antisymmetry.
		if rev, _ := CompareVersions(c.b, c.a); rev != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d; want %d", c.b, c.a, rev, -c.want)
		}
	}
}

func TestValidVersion(t *testing.T) {
	valid := []string{"0.0.0", "1.2.3", "v1.2.3", "10.20.30", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7",
		"1.0.0-x.7.z.92", "1.0.0-x-y-z.--", "1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85", "0.0.0-dev", "1.0.0-0A"}
	for _, v := range valid {
		if !ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = false", v)
		}
	}
	invalid := []string{"", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03", "1.2.3-", "1.2.3-01", "1.2.3-a..b",
		"1.2.3+", "V1.2.3", "vv1.2.3", " 1.2.3", "1.2.3 ", "1.2.3-a b", "latest", "1.2.x", "-1.2.3", "1.2.3\n",
		"1.2.3-ä", "../1.2.3", "18446744073709551616.0.0", "1.0.0-" + strings.Repeat("a", 64)}
	for _, v := range invalid {
		if ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = true", v)
		}
		if _, ok := CompareVersions(v, "1.0.0"); ok {
			t.Errorf("CompareVersions(%q, ...) accepted an invalid version", v)
		}
	}
}

func TestSameVersion(t *testing.T) {
	if !SameVersion("v1.2.3", "1.2.3") || !SameVersion("1.2.3", "1.2.3") {
		t.Error("the v prefix must not matter")
	}
	if SameVersion("1.2.3+a", "1.2.3+b") || SameVersion("1.2.3", "1.2.4") || SameVersion("1.2.3-rc.1", "1.2.3") {
		t.Error("different builds reported as the same version")
	}
}
