package platform

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseWho(t *testing.T) {
	if got, want := ParseWho(fixture(t, "who_linux.txt")), []string{"alice", "bob"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("linux: %v", got)
	}
	if got, want := ParseWho(fixture(t, "who_darwin.txt")), []string{"admin", "shinky"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin: %v", got)
	}
	if got := ParseWho(""); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
}

func TestLoginctlConsoleUser(t *testing.T) {
	ids := ParseLoginctlSessionIDs(fixture(t, "loginctl_list.txt"))
	if want := []string{"2", "c1", "5"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("session ids %v", ids)
	}
	var sessions []LoginSession
	for _, id := range ids {
		sessions = append(sessions, ParseLoginctlSession(fixture(t, "loginctl_show_"+id+".txt")))
	}
	if s := sessions[0]; s.Name != "alice" || !s.Active || s.Remote || s.Class != "user" || s.Type != "wayland" || s.Seat != "seat0" {
		t.Fatalf("session 2 parsed as %+v", s)
	}
	// The greeter and the remote SSH session are not the console user.
	if got := PickConsoleUser(sessions); got != "alice" {
		t.Fatalf("console user %q", got)
	}
	if got := PickConsoleUser(sessions[1:]); got != "" {
		t.Fatalf("greeter / remote session picked as console user: %q", got)
	}
	if got, want := LoggedInFromSessions(sessions), []string{"alice", "bob"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("logged in: %v", got)
	}
	// A text console is used when there is no graphical session.
	tty := []LoginSession{{Name: "carol", Active: true, Class: "user", Type: "tty", Seat: "seat0"}}
	if got := PickConsoleUser(tty); got != "carol" {
		t.Fatalf("tty console user %q", got)
	}
}

func TestParsePasswdLine(t *testing.T) {
	e, ok := ParsePasswdLine("alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash\n")
	if !ok || e.Name != "alice" || e.UID != "1000" || e.GID != "1000" || e.Home != "/home/alice" || e.Shell != "/bin/bash" {
		t.Fatalf("%+v %v", e, ok)
	}
	for _, bad := range []string{"", "alice:x:abc:1000::/home/alice:/bin/sh", "too:few:fields", ":x:1:1::/:/bin/sh"} {
		if _, ok := ParsePasswdLine(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidAccountKey(t *testing.T) {
	for _, ok := range []string{"alice", "1000", "j.doe", "svc_backup", "user@example.com", `CORP\\alice`, "machine$"} {
		if !validAccountKey(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "-s", "--service=x", "a b", "a;b", "a\nb", "$(id)x y", "a/b"} {
		if validAccountKey(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseIoreg(t *testing.T) {
	out := fixture(t, "ioreg.txt")
	if got := ParseIoregValue(out, "IOPlatformUUID"); got != "0A1B2C3D-4E5F-5A6B-8C7D-9E0F1A2B3C4D" {
		t.Fatalf("uuid %q", got)
	}
	if got := ParseIoregValue(out, "IOPlatformSerialNumber"); got != "FVFXK0TESTQ6" {
		t.Fatalf("serial %q", got)
	}
	if got := ParseIoregValue(out, "DoesNotExist"); got != "" {
		t.Fatalf("missing key gave %q", got)
	}
	// Non-string properties are not mistaken for strings.
	if got := ParseIoregValue(out, "model"); got != "" {
		t.Fatalf("data property parsed as string: %q", got)
	}
}

func TestParseMachineID(t *testing.T) {
	if got := ParseMachineID("  4C4C4544-0042-3510-8052-B7C04F4E4D32\n"); got != "4c4c4544-0042-3510-8052-b7c04f4e4d32" {
		t.Fatalf("%q", got)
	}
}

func TestMergeEnv(t *testing.T) {
	got := MergeEnv([]string{"PATH=/bin", "HOME=/root", "X=1"}, []string{"X=2", "NEW=n"}, false)
	want := []string{"PATH=/bin", "HOME=/root", "X=2", "NEW=n"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	// Windows: names are case-insensitive, and "=C:=C:\\" style entries pass through.
	got = MergeEnv([]string{`=C:=C:\Users`, "Path=C:\\Windows", "TEMP=a"}, []string{"PATH=C:\\Tools", "temp=b"}, true)
	want = []string{`=C:=C:\Users`, "PATH=C:\\Tools", "temp=b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}
