package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// mounts reads a "device|mountpoint|fstype" fixture.
func mounts(t *testing.T, name string) []Partition {
	t.Helper()
	var parts []Partition
	for _, line := range strings.Split(strings.TrimSpace(string(fixture(t, name))), "\n") {
		f := strings.Split(line, "|")
		if len(f) != 3 {
			t.Fatalf("bad fixture line %q", line)
		}
		parts = append(parts, Partition{Device: f[0], MountPoint: f[1], FSType: f[2]})
	}
	return parts
}

func mountPoints(parts []Partition) []string {
	out := []string{}
	for _, p := range parts {
		out = append(out, p.MountPoint)
	}
	return out
}

// ---- macOS ----

func TestDarwinSwVers(t *testing.T) {
	name, version, build := ParseSwVers(string(fixture(t, "darwin_sw_vers.txt")))
	if name != "macOS" || version != "15.6.1" || build != "24G90" {
		t.Fatalf("%q %q %q", name, version, build)
	}
}

func TestDarwinSystemProfiler(t *testing.T) {
	hw, err := ParseSystemProfilerHardware(fixture(t, "darwin_system_profiler.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := Hardware{Serial: "FVFXK0TESTQ6", Manufacturer: "Apple Inc.", Model: "MacBook Air (Mac14,2)"}
	if hw != want {
		t.Fatalf("%+v", hw)
	}
	if _, err := ParseSystemProfilerHardware([]byte(`{"SPHardwareDataType":[]}`)); err == nil {
		t.Fatal("empty result accepted")
	}
	if _, err := ParseSystemProfilerHardware([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestDarwinDiskFilter(t *testing.T) {
	got := mountPoints(FilterPartitions(protocol.OSMacOS, mounts(t, "darwin_mounts.txt")))
	want := []string{"/", "/Volumes/Backup", "/Volumes/USB STICK", "/Volumes/Install macOS"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

// ---- Linux ----

func TestLinuxOSRelease(t *testing.T) {
	cases := []struct {
		file string
		want protocol.OSInfo
	}{
		{"linux_os_release_ubuntu.txt", protocol.OSInfo{Family: "linux", Name: "Ubuntu", Version: "24.04", Build: "24.04.1 LTS (Noble Numbat)", Kernel: "6.8.0-45-generic"}},
		{"linux_os_release_rocky.txt", protocol.OSInfo{Family: "linux", Name: "Rocky Linux", Version: "9.4", Build: "9.4 (Blue Onyx)", Kernel: "6.8.0-45-generic"}},
		{"linux_os_release_arch.txt", protocol.OSInfo{Family: "linux", Name: "Arch Linux", Version: "", Build: "rolling", Kernel: "6.8.0-45-generic"}},
	}
	for _, c := range cases {
		got := LinuxOSInfo(ParseOSRelease(string(fixture(t, c.file))), "6.8.0-45-generic")
		if got != c.want {
			t.Errorf("%s: %+v", c.file, got)
		}
	}
	if got := LinuxOSInfo(ParseOSRelease(""), "k"); got.Name != "Linux" || got.Family != "linux" {
		t.Fatalf("missing os-release: %+v", got)
	}
	m := ParseOSRelease(string(fixture(t, "linux_os_release_rocky.txt")))
	if m["ID_LIKE"] != "rhel centos fedora" || m["ANSI_COLOR"] != "0;32" {
		t.Fatalf("quoting: %v", m)
	}
}

func TestLinuxDiskFilter(t *testing.T) {
	got := mountPoints(FilterPartitions(protocol.OSLinux, mounts(t, "linux_mounts.txt")))
	// No tmpfs/proc/sysfs/cgroup, no snap or loop mounts, no docker internals,
	// no network filesystems, and /dev/sda1 only once.
	want := []string{"/", "/boot/efi", "/home", "/mnt/data", "/media/usb"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	// In a container the overlay root is the one disk worth reporting.
	got = mountPoints(FilterPartitions(protocol.OSLinux, mounts(t, "linux_container_mounts.txt")))
	if want := []string{"/"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("container: got %v", got)
	}
}

func TestLinuxDMIStrings(t *testing.T) {
	for in, want := range map[string]string{
		"PF3ABC12\n":               "PF3ABC12",
		"  Dell Inc.  ":            "Dell Inc.",
		"To Be Filled By O.E.M.\n": "",
		"Default string":           "",
		"System Product Name":      "",
		"Not Specified":            "",
		"0":                        "",
		"":                         "",
		"Raspberry Pi 5\x00":       "Raspberry Pi 5",
	} {
		if got := CleanHardwareString(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestTimezoneFromLink(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/share/zoneinfo/Europe/Berlin":                   "Europe/Berlin",
		"/var/db/timezone/zoneinfo/America/Argentina/Cordoba": "America/Argentina/Cordoba",
		"../usr/share/zoneinfo/UTC":                           "UTC",
		"/usr/share/zoneinfo/posix/Asia/Kolkata":              "Asia/Kolkata",
		"/etc/somewhere/else":                                 "",
	} {
		if got := TimezoneFromLink(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// ---- Windows ----

func TestWindowsOSInfo(t *testing.T) {
	cases := []struct {
		product, display, release, build string
		ubr                              uint64
		want                             protocol.OSInfo
	}{
		// Windows 11 reports "Windows 10 Pro" in the registry; the build number decides.
		{"Windows 10 Pro", "23H2", "2009", "22631", 4460,
			protocol.OSInfo{Family: "windows", Name: "Windows 11 Pro", Version: "23H2", Build: "22631.4460", Kernel: "10.0.22631"}},
		{"Windows 10 Enterprise", "22H2", "2009", "19045", 5011,
			protocol.OSInfo{Family: "windows", Name: "Windows 10 Enterprise", Version: "22H2", Build: "19045.5011", Kernel: "10.0.19045"}},
		{"Windows Server 2022 Standard", "21H2", "2009", "20348", 2762,
			protocol.OSInfo{Family: "windows", Name: "Windows Server 2022 Standard", Version: "21H2", Build: "20348.2762", Kernel: "10.0.20348"}},
		// Server 2016 has no DisplayVersion; ReleaseId is used.
		{"Windows Server 2016 Datacenter", "", "1607", "14393", 7428,
			protocol.OSInfo{Family: "windows", Name: "Windows Server 2016 Datacenter", Version: "1607", Build: "14393.7428", Kernel: "10.0.14393"}},
		{"", "", "", "", 0, protocol.OSInfo{Family: "windows", Name: "Windows"}},
	}
	for _, c := range cases {
		if got := WindowsOSInfo(c.product, c.display, c.release, c.build, c.ubr); got != c.want {
			t.Errorf("%q build %s: %+v", c.product, c.build, got)
		}
	}
}

func TestWindowsHardwareJSON(t *testing.T) {
	hw, err := ParseWindowsHardwareJSON(fixture(t, "windows_cim.json")) // has a BOM and CRLF, as PowerShell writes it
	if err != nil {
		t.Fatal(err)
	}
	if want := (Hardware{Serial: "PF3TESTX", Manufacturer: "LENOVO", Model: "21HMCTO1WW"}); hw != want {
		t.Fatalf("%+v", hw)
	}
	// Placeholder strings from white-box PCs are blanked.
	hw, err = ParseWindowsHardwareJSON(fixture(t, "windows_cim_vm.json"))
	if err != nil || hw != (Hardware{}) {
		t.Fatalf("%+v %v", hw, err)
	}
	// JSON null (no serial on some VMs).
	hw, err = ParseWindowsHardwareJSON(fixture(t, "windows_cim_null.json"))
	if err != nil || hw.Serial != "" || hw.Manufacturer != "Microsoft Corporation" || hw.Model != "Virtual Machine" {
		t.Fatalf("%+v %v", hw, err)
	}
	if _, err := ParseWindowsHardwareJSON([]byte("Get-CimInstance : Access denied")); err == nil {
		t.Fatal("error text accepted as JSON")
	}
}

func TestWindowsDiskFilter(t *testing.T) {
	got := mountPoints(FilterPartitions(protocol.OSWindows, mounts(t, "windows_mounts.txt")))
	if want := []string{"C:", "D:", "F:", "H:"}; !reflect.DeepEqual(got, want) { // no CD-ROM, no empty drive
		t.Fatalf("got %v", got)
	}
}

// ---- common ----

func TestFilterInterfaces(t *testing.T) {
	raw := []RawInterface{
		{Name: "lo0", Loopback: true, Up: true, Addrs: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "en0", MAC: "A4:83:E7:11:22:33", Up: true, Addrs: []string{"192.168.1.23/24", "fe80::1c2d:3e4f:5a6b:7c8d/64", "2001:db8::23/64"}},
		{Name: "awdl0", MAC: "0e:11:22:33:44:55", Up: true, Addrs: []string{"fe80::c11:22ff:fe33:4455/64"}}, // link-local only
		{Name: "en5", MAC: "ac:de:48:00:11:22", Up: false, Addrs: []string{"10.0.0.5/8"}},                   // down
		{Name: "utun3", Up: true, Addrs: []string{"100.64.0.7/32"}},                                         // VPN without MAC
		{Name: "eth1", MAC: "02:42:ac:11:00:02", Up: true, Addrs: []string{"garbage", "172.17.0.2"}},
	}
	got := FilterInterfaces(raw)
	want := []protocol.NetworkInterface{
		{Name: "en0", MAC: "a4:83:e7:11:22:33", IPv4: []string{"192.168.1.23"}, IPv6: []string{"2001:db8::23"}},
		{Name: "eth1", MAC: "02:42:ac:11:00:02", IPv4: []string{"172.17.0.2"}, IPv6: []string{}},
		{Name: "utun3", MAC: "", IPv4: []string{"100.64.0.7"}, IPv6: []string{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := FilterInterfaces(nil); got == nil || len(got) != 0 {
		t.Fatal("expected an empty, non-nil list")
	}
}
