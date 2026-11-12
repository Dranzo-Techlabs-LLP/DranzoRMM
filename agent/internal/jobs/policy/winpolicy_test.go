package policy

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

const netAccountsEN = "Force user logoff how long after time expires?:       Never\r\n" +
	"Minimum password age (days):                          0\r\n" +
	"Maximum password age (days):                          42\r\n" +
	"Minimum password length:                              8\r\n" +
	"Length of password history maintained:                None\r\n" +
	"Lockout threshold:                                    Never\r\n" +
	"Lockout duration (minutes):                           30\r\n" +
	"Lockout observation window (minutes):                 30\r\n" +
	"Computer role:                                        WORKSTATION\r\n" +
	"The command completed successfully.\r\n\r\n"

const netAccountsDE = "Abmeldung erzwingen nach:                                   Nie\r\n" +
	"Minimales Kennwortalter (Tage):                             0\r\n" +
	"Maximales Kennwortalter (Tage):                             Unbegrenzt\r\n" +
	"Minimale Kennwortlänge:                                     0\r\n" +
	"Länge des Kennwortprotokolls:                               Keine\r\n" +
	"Sperrschwelle:                                              Nie\r\n" +
	"Sperrdauer (Minuten):                                       30\r\n" +
	"Sperrüberwachungsfenster (Minuten):                         30\r\n" +
	"Computerrolle:                                              ARBEITSSTATION\r\n" +
	"Der Befehl wurde erfolgreich ausgeführt.\r\n"

func TestParseNetAccounts(t *testing.T) {
	p, err := ParseNetAccounts(netAccountsEN)
	if err != nil || p.MinLength != 8 || p.MaxAgeDays != 42 || p.Complexity != nil {
		t.Errorf("english: %+v %v", p, err)
	}
	// "Unlimited" means passwords never expire.
	p, err = ParseNetAccounts(strings.Replace(netAccountsEN, "42", "Unlimited", 1))
	if err != nil || p.MaxAgeDays != 0 || p.MinLength != 8 {
		t.Errorf("unlimited: %+v %v", p, err)
	}
	// Another display language: the values are taken by position.
	p, err = ParseNetAccounts(netAccountsDE)
	if err != nil || p.MinLength != 0 || p.MaxAgeDays != 0 {
		t.Errorf("german: %+v %v", p, err)
	}
	p, err = ParseNetAccounts(strings.Replace(strings.Replace(netAccountsDE, "Unbegrenzt", "90", 1), "länge:                                     0", "länge:                                     10", 1))
	if err != nil || p.MinLength != 10 || p.MaxAgeDays != 90 {
		t.Errorf("german with values: %+v %v", p, err)
	}
	for _, bad := range []string{"", "System error 5 has occurred.\r\n\r\nAccess is denied.\r\n", "Minimum password length: many\r\nMaximum password age (days): 42\r\n"} {
		if _, err := ParseNetAccounts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func utf16le(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func TestParseSeceditComplexity(t *testing.T) {
	inf := "[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordAge = 0\r\nMaximumPasswordAge = 42\r\nMinimumPasswordLength = 8\r\n" +
		"PasswordComplexity = 1\r\nPasswordHistorySize = 0\r\n[Event Audit]\r\nAuditSystemEvents = 0\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n"
	// secedit writes UTF-16 LE with a byte order mark.
	if on, ok := ParseSeceditComplexity(utf16le(inf)); !ok || !on {
		t.Errorf("utf-16: %v %v", on, ok)
	}
	if on, ok := ParseSeceditComplexity([]byte(strings.Replace(inf, "PasswordComplexity = 1", "PasswordComplexity = 0", 1))); !ok || on {
		t.Errorf("plain, off: %v %v", on, ok)
	}
	// The key outside [System Access] does not count; garbage is "unknown".
	if _, ok := ParseSeceditComplexity([]byte("[Other]\r\nPasswordComplexity = 1\r\n")); ok {
		t.Error("wrong section accepted")
	}
	if _, ok := ParseSeceditComplexity([]byte("[System Access]\r\nPasswordComplexity = maybe\r\n")); ok {
		t.Error("garbage value accepted")
	}
	if _, ok := ParseSeceditComplexity(nil); ok {
		t.Error("empty accepted")
	}
}

func TestEvalUSB(t *testing.T) {
	cases := []struct {
		state   usbState
		blocked bool
		detail  string
	}{
		{usbState{StartKnown: true, Start: 3}, false, "USBSTOR Start=3; no removable storage deny policy"},
		{usbState{StartKnown: true, Start: 4}, true, "USBSTOR Start=4"},
		{usbState{StartKnown: true, Start: 3, DenyAll: true}, true, "deny all access"},
		{usbState{StartKnown: true, Start: 3, DenyRead: true, DenyWrite: true}, true, "deny read and write"},
		// Write-only blocking still lets data be read from a stick: not "blocked".
		{usbState{StartKnown: true, Start: 3, DenyWrite: true}, false, "partial"},
		{usbState{}, false, "USBSTOR service not present"},
	}
	for _, c := range cases {
		blocked, detail := evalUSB(c.state)
		if blocked != c.blocked || !strings.Contains(detail, c.detail) {
			t.Errorf("%+v: %v %q", c.state, blocked, detail)
		}
	}
}

func TestPasswordGapsAndArgs(t *testing.T) {
	n := func(v int) *int { return &v }
	on, off := true, false

	gaps, setMin, setMax, cg := passwordGaps(PasswordPolicy{MinLength: 12, MaxAgeDays: 30, Complexity: &on}, passwordWant{MinLength: n(12), MaxAgeDays: n(90), Complexity: &on})
	if len(gaps) != 0 || setMin != nil || setMax != nil || cg {
		t.Errorf("compliant: %v", gaps)
	}
	gaps, setMin, setMax, cg = passwordGaps(PasswordPolicy{MinLength: 6, MaxAgeDays: 0, Complexity: &off}, passwordWant{MinLength: n(12), MaxAgeDays: n(90), Complexity: &on})
	if len(gaps) != 3 || *setMin != 12 || *setMax != 90 || !cg {
		t.Errorf("all short: %v", gaps)
	}
	// Only tightening: a longer current minimum and a shorter age are left alone.
	_, setMin, setMax, _ = passwordGaps(PasswordPolicy{MinLength: 14, MaxAgeDays: 30}, passwordWant{MinLength: n(8), MaxAgeDays: n(90)})
	if setMin != nil || setMax != nil {
		t.Error("would loosen the policy")
	}

	// The argv of `net accounts`: integers only, one element per option.
	if got := netAccountsArgs(n(12), n(90)); !reflect.DeepEqual(got, []string{"accounts", "/minpwlen:12", "/maxpwage:90"}) {
		t.Errorf("%q", got)
	}
	if got := netAccountsArgs(nil, n(60)); !reflect.DeepEqual(got, []string{"accounts", "/maxpwage:60"}) {
		t.Errorf("%q", got)
	}
	if got := netAccountsArgs(n(8), nil); !reflect.DeepEqual(got, []string{"accounts", "/minpwlen:8"}) {
		t.Errorf("%q", got)
	}
}

// TestRemediationScripts guards the fixed Windows remediation scripts.
func TestRemediationScripts(t *testing.T) {
	scripts := map[string]string{"PSEnableFirewall": PSEnableFirewall, "PSEnableDefender": PSEnableDefender, "PSRemoveAdmin": PSRemoveAdmin}
	for name, s := range scripts {
		// One complete statement on one line, with its own exit codes.
		if strings.Count(s, "\n") != 1 || !strings.HasSuffix(s, "\n") {
			t.Errorf("%s: must be exactly one line", name)
		}
		if strings.Count(s, "{") != strings.Count(s, "}") || strings.Count(s, "(") != strings.Count(s, ")") || strings.Count(s, "'")%2 != 0 {
			t.Errorf("%s: unbalanced", name)
		}
		if !strings.HasPrefix(s, "try{") || !strings.Contains(s, ";exit 0}catch{") || !strings.Contains(s, ";exit 1}") {
			t.Errorf("%s: no explicit exit codes", name)
		}
		// Nothing is formatted into a script.
		if strings.ContainsAny(s, "%") {
			t.Errorf("%s: contains a format verb", name)
		}
		low := strings.ToLower(s)
		for _, bad := range []string{"invoke-expression", "iex ", "downloadstring", "invoke-webrequest", "-encodedcommand", "remove-localuser", "disable-localuser", "uninstall", "remove-item", "remove-mppreference"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s: contains %q", name, bad)
			}
		}
	}
	// Firewall: on, never off.
	if !strings.Contains(PSEnableFirewall, "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True") || strings.Contains(PSEnableFirewall, "False") {
		t.Errorf("PSEnableFirewall: %s", PSEnableFirewall)
	}
	// Group membership: by the well-known SID, member from the environment,
	// and the account itself is not deleted or disabled.
	if !strings.Contains(PSRemoveAdmin, "Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $env:"+EnvAdminMember+" ") {
		t.Errorf("PSRemoveAdmin: %s", PSRemoveAdmin)
	}
}

func TestIsDomainControllerProductType(t *testing.T) {
	for value, want := range map[string]bool{"LanmanNT": true, "lanmannt ": true, "WinNT": false, "ServerNT": false, "": false} {
		if IsDomainControllerProductType(value) != want {
			t.Errorf("%q", value)
		}
	}
}
