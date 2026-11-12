package update

import (
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func validOffer(version string) protocol.UpdateAvailable {
	return protocol.UpdateAvailable{
		Version:   version,
		BlobID:    "3f2c1a9e-5b7d-4e1f-8a6b-0c9d8e7f6a5b",
		SHA256:    strings.Repeat("0123456789abcdef", 4),
		SizeBytes: 20 << 20,
		Ring:      "pilot",
	}
}

func TestDecide(t *testing.T) {
	failed := func(v string) bool { return SameVersion(v, "1.5.0") || SameVersion(v, "0.9.0") }
	cases := []struct {
		name    string
		running string
		offer   string
		force   bool
		want    Action
	}{
		{"newer patch", "1.0.0", "1.0.1", false, ActionInstall},
		{"newer major", "1.9.9", "2.0.0", false, ActionInstall},
		{"newer, v prefix", "1.0.0", "v1.1.0", false, ActionInstall},
		{"release over its pre-release", "1.0.0-rc.1", "1.0.0", false, ActionInstall},
		{"newer pre-release", "1.0.0-rc.1", "1.0.0-rc.2", false, ActionInstall},
		{"dev build is older than any release", "0.0.0-dev", "0.1.0", false, ActionInstall},
		{"same", "1.0.0", "1.0.0", false, ActionIgnore},
		{"same, v prefix", "1.0.0", "v1.0.0", false, ActionIgnore},
		{"same with force", "1.0.0", "1.0.0", true, ActionIgnore},
		{"same with force, v prefix", "v1.0.0", "1.0.0", true, ActionIgnore},
		{"older", "1.1.0", "1.0.9", false, ActionIgnore},
		{"older with force (downgrade)", "1.1.0", "1.0.9", true, ActionInstall},
		{"pre-release of the running release", "1.0.0", "1.0.0-rc.1", false, ActionIgnore},
		{"pre-release of the running release, force", "1.0.0", "1.0.0-rc.1", true, ActionInstall},
		{"equal precedence, other build", "1.0.0+a", "1.0.0+b", false, ActionIgnore},
		{"equal precedence, other build, force", "1.0.0+a", "1.0.0+b", true, ActionInstall},
		{"newer but failed before", "1.0.0", "1.5.0", false, ActionRefuse},
		{"newer but failed before, force", "1.0.0", "1.5.0", true, ActionRefuse},
		{"failed before, v prefix", "1.0.0", "v1.5.0", false, ActionRefuse},
		{"older and failed before, force", "1.0.0", "0.9.0", true, ActionRefuse},
		{"older and failed before, no force", "1.0.0", "0.9.0", false, ActionIgnore},
		{"running version is not semver", "devel", "0.0.1", false, ActionInstall},
	}
	for _, c := range cases {
		upd := validOffer(c.offer)
		upd.Force = c.force
		if got := Decide(c.running, upd, failed); got.Action != c.want {
			t.Errorf("%s: running %s, offer %s, force %v: action %d (%s), want %d",
				c.name, c.running, c.offer, c.force, got.Action, got.Reason, c.want)
		}
	}
	// Without a failed list everything valid and newer installs.
	if got := Decide("1.0.0", validOffer("1.5.0"), nil); got.Action != ActionInstall {
		t.Errorf("nil failed list: %+v", got)
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(validOffer("1.2.3")); err != nil {
		t.Fatalf("valid offer refused: %v", err)
	}
	cases := map[string]func(*protocol.UpdateAvailable){
		"empty version":        func(u *protocol.UpdateAvailable) { u.Version = "" },
		"not semver":           func(u *protocol.UpdateAvailable) { u.Version = "latest" },
		"two components":       func(u *protocol.UpdateAvailable) { u.Version = "1.2" },
		"path in version":      func(u *protocol.UpdateAvailable) { u.Version = "1.2.3/../../x" },
		"leading zero":         func(u *protocol.UpdateAvailable) { u.Version = "01.2.3" },
		"overlong version":     func(u *protocol.UpdateAvailable) { u.Version = "1.2.3-" + strings.Repeat("a", 80) },
		"blob id":              func(u *protocol.UpdateAvailable) { u.BlobID = "../../etc/passwd" },
		"empty blob id":        func(u *protocol.UpdateAvailable) { u.BlobID = "" },
		"short sha256":         func(u *protocol.UpdateAvailable) { u.SHA256 = "abcdef" },
		"sha256 not hex":       func(u *protocol.UpdateAvailable) { u.SHA256 = strings.Repeat("zz", 32) },
		"sha256 too long":      func(u *protocol.UpdateAvailable) { u.SHA256 = strings.Repeat("ab", 33) },
		"empty sha256":         func(u *protocol.UpdateAvailable) { u.SHA256 = "" },
		"zero size":            func(u *protocol.UpdateAvailable) { u.SizeBytes = 0 },
		"negative size":        func(u *protocol.UpdateAvailable) { u.SizeBytes = -1 },
		"implausibly small":    func(u *protocol.UpdateAvailable) { u.SizeBytes = MinSizeBytes - 1 },
		"implausibly large":    func(u *protocol.UpdateAvailable) { u.SizeBytes = MaxSizeBytes + 1 },
		"4 GiB (blob maximum)": func(u *protocol.UpdateAvailable) { u.SizeBytes = 4 << 30 },
	}
	for name, mutate := range cases {
		upd := validOffer("1.2.3")
		mutate(&upd)
		if err := Validate(upd); err == nil {
			t.Errorf("%s: accepted", name)
		}
		// An invalid offer is refused whatever the versions and flags say.
		upd.Force = true
		if got := Decide("0.0.1", upd, nil); got.Action != ActionRefuse || !strings.HasPrefix(got.Reason, "invalid update") {
			t.Errorf("%s: decision %+v", name, got)
		}
	}
	for _, size := range []int64{MinSizeBytes, MaxSizeBytes} {
		upd := validOffer("1.2.3")
		upd.SizeBytes = size
		if err := Validate(upd); err != nil {
			t.Errorf("size %d refused: %v", size, err)
		}
	}
}

func TestParseVersionOutput(t *testing.T) {
	good := "dranzo-agent 1.2.3 (" + platform.OSFamily + ")\n"
	if v, err := ParseVersionOutput(good); err != nil || v != "1.2.3" {
		t.Fatalf("%q: %q, %v", good, v, err)
	}
	if v, err := ParseVersionOutput("dranzo-agent 1.2.3-rc.1+b7\r\n"); err != nil || v != "1.2.3-rc.1+b7" {
		t.Fatalf("without OS: %q, %v", v, err)
	}
	for _, bad := range []string{"", "\n", "1.2.3", "dranzo-agent", "other-agent 1.2.3 (linux)", "usage: dranzo-agent ...",
		"dranzo-agent 1.2.3 (beos)", "error\ndranzo-agent 1.2.3"} {
		if v, err := ParseVersionOutput(bad); err == nil {
			t.Errorf("%q accepted as version %q", bad, v)
		}
	}
}

func TestRunMode(t *testing.T) {
	cases := []struct {
		args                []string
		running, foreground bool
	}{
		{nil, false, false},
		{[]string{"dranzo-agent"}, false, false},
		{[]string{"dranzo-agent", "version"}, false, false},
		{[]string{"dranzo-agent", "enroll", "--data-dir", "/x"}, false, false},
		{[]string{"dranzo-agent", "install", "--server", "https://x"}, false, false},
		{[]string{"dranzo-agent", "run"}, true, false},
		{[]string{"dranzo-agent", "run", "--data-dir", "/x"}, true, false},
		{[]string{"dranzo-agent", "run", "--foreground"}, true, true},
		{[]string{"dranzo-agent", "run", "-foreground", "-debug"}, true, true},
		{[]string{"dranzo-agent", "run", "--data-dir=/x", "--foreground=true"}, true, true},
		{[]string{"dranzo-agent", "run", "--foreground=false"}, true, false},
		{[]string{"dranzo-agent", "run", "--no-such-flag"}, false, false},
	}
	for _, c := range cases {
		running, fg := RunMode(c.args)
		if running != c.running || fg != c.foreground {
			t.Errorf("RunMode(%v) = %v, %v; want %v, %v", c.args, running, fg, c.running, c.foreground)
		}
	}
}
