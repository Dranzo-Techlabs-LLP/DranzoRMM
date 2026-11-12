package posture

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Disk encryption methods and states (PROTOCOL.md section 7.3).
const (
	MethodBitLocker = "bitlocker"
	MethodFileVault = "filevault"
	MethodLUKS      = "luks"
	MethodNone      = "none"

	StatusEncrypted  = "encrypted"
	StatusDecrypted  = "decrypted"
	StatusInProgress = "in_progress"
	StatusUnknown    = "unknown"
)

// ---- Windows ----

type bitLockerVolume struct {
	MountPoint       string `json:"mountPoint"`
	VolumeType       string `json:"volumeType"`
	VolumeStatus     string `json:"volumeStatus"`
	ProtectionStatus string `json:"protectionStatus"`
	DriveType        string `json:"driveType"`
}

type bitLockerReport struct {
	Volumes   list[bitLockerVolume] `json:"volumes"`
	Error     string                `json:"error"`
	ManageBde string                `json:"manageBde"`
}

// bitLockerState maps BitLocker's conversion and protection state to the
// protocol values.
//
// A fully encrypted volume whose protection is off is "suspended": the data
// is encrypted but the key is stored in the clear, so the volume is not
// protected. The protocol has no value for that; it is reported as "unknown"
// (never as "encrypted"), and the disk encryption policy check treats
// anything but "encrypted" as not compliant.
func bitLockerState(conversion, protection string) (method, status string) {
	c := strings.ToLower(strings.ReplaceAll(conversion, " ", ""))
	p := strings.ToLower(strings.ReplaceAll(protection, " ", ""))
	protectionOn := p == "on" || p == "1" || p == "protectionon"
	switch {
	case c == "fullydecrypted" || c == "0":
		return MethodNone, StatusDecrypted
	case strings.Contains(c, "inprogress") || strings.Contains(c, "paused") || c == "2" || c == "3" || c == "4" || c == "5":
		return MethodBitLocker, StatusInProgress
	case c == "fullyencrypted" || c == "1" || c == "usedspaceonlyencrypted":
		if protectionOn {
			return MethodBitLocker, StatusEncrypted
		}
		return MethodBitLocker, StatusUnknown
	}
	return MethodBitLocker, StatusUnknown
}

// ParseBitLocker turns the output of PSBitLocker into volumes. Removable
// drives are left out (only fixed volumes describe the device's posture).
func ParseBitLocker(data []byte) ([]protocol.DiskEncryption, error) {
	var r bitLockerReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("BitLocker status: %w", err)
	}
	if r.Volumes.Set {
		out := []protocol.DiskEncryption{}
		for _, v := range r.Volumes.Items {
			mount := strings.TrimSpace(v.MountPoint)
			if mount == "" {
				continue
			}
			if dt := strings.ToLower(strings.TrimSpace(v.DriveType)); dt != "" && dt != "fixed" {
				continue
			}
			method, status := bitLockerState(v.VolumeStatus, v.ProtectionStatus)
			out = append(out, protocol.DiskEncryption{Volume: mount, Method: method, Status: status})
		}
		sortVolumes(out)
		return out, nil
	}
	if strings.TrimSpace(r.ManageBde) != "" {
		vols, err := ParseManageBde(r.ManageBde)
		if err == nil {
			return vols, nil
		}
	}
	return nil, Unsupportedf("BitLocker status is not available on this edition (%s)", OneLine(r.Error, 300))
}

// ParseManageBde parses the English text output of `manage-bde -status`:
//
//	Volume C: [Windows]
//	[OS Volume]
//
//	    Conversion Status:    Fully Encrypted
//	    Protection Status:    Protection On
//
// On a Windows display language other than English the labels differ and an
// error is returned (the caller then reports the section as unsupported).
func ParseManageBde(out string) ([]protocol.DiskEncryption, error) {
	type vol struct{ mount, conversion, protection string }
	var vols []vol
	var cur *vol
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(l, "Volume "); ok {
			mount, _, _ := strings.Cut(rest, " ")
			if mount != "" {
				vols = append(vols, vol{mount: mount})
				cur = &vols[len(vols)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		if v, ok := strings.CutPrefix(l, "Conversion Status:"); ok {
			cur.conversion = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(l, "Protection Status:"); ok {
			cur.protection = strings.TrimSpace(v)
		}
	}
	result := []protocol.DiskEncryption{}
	for _, v := range vols {
		if v.conversion == "" {
			continue
		}
		method, status := bitLockerState(v.conversion, v.protection)
		result = append(result, protocol.DiskEncryption{Volume: v.mount, Method: method, Status: status})
	}
	if len(result) == 0 {
		return nil, errors.New("manage-bde output not recognised")
	}
	sortVolumes(result)
	return result, nil
}

// ---- macOS ----

// ParseFdesetupStatus parses `fdesetup status`:
//
//	FileVault is On.
//	FileVault is Off.
//	FileVault is On.\nEncryption in progress: Percent completed = 43
//	FileVault is Off.\nDecryption in progress: Percent completed = 8
//	FileVault is On, but needs to be restarted to finish.
func ParseFdesetupStatus(out string) (protocol.DiskEncryption, error) {
	s := strings.ToLower(out)
	v := protocol.DiskEncryption{Volume: "/", Method: MethodFileVault}
	switch {
	case strings.Contains(s, "encryption in progress"), strings.Contains(s, "decryption in progress"),
		strings.Contains(s, "needs to be restarted"):
		v.Status = StatusInProgress
	case strings.Contains(s, "filevault is on"):
		v.Status = StatusEncrypted
	case strings.Contains(s, "filevault is off"):
		v.Method, v.Status = MethodNone, StatusDecrypted
	default:
		return protocol.DiskEncryption{}, fmt.Errorf("unrecognised fdesetup output: %q", OneLine(out, 120))
	}
	return v, nil
}

// ---- Linux ----

type lsblkDevice struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	FSType      *string       `json:"fstype"`
	MountPoint  *string       `json:"mountpoint"`
	MountPoints []*string     `json:"mountpoints"`
	Children    []lsblkDevice `json:"children"`
}

type lsblkReport struct {
	BlockDevices []lsblkDevice `json:"blockdevices"`
}

// skipMount reports whether a mount point is left out of the encryption
// report: boot / EFI partitions (never encrypted by design), swap, and
// read-only package images.
func skipMount(mp string) bool {
	if !strings.HasPrefix(mp, "/") {
		return true // "[SWAP]" and similar
	}
	switch mp {
	case "/boot", "/boot/efi", "/efi", "/boot/firmware":
		return true
	}
	for _, prefix := range []string{"/snap/", "/var/lib/snapd/", "/run/", "/boot/efi/"} {
		if strings.HasPrefix(mp, prefix) {
			return true
		}
	}
	return false
}

const lsblkMaxDepth = 16

// ParseLsblk turns `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS` (or MOUNTPOINT
// on older util-linux) into the encryption state of "/" and the data
// mounts: a file system is "luks / encrypted" when a dm-crypt device (lsblk
// type "crypt") is among the devices it sits on, otherwise "none /
// decrypted". If "/" is not on a block device lsblk lists (containers, ZFS,
// network roots) the state is unknown and an *UnsupportedError is returned.
func ParseLsblk(data []byte) ([]protocol.DiskEncryption, error) {
	var r lsblkReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	// A device with several parents (RAID, multi-device LVM) is listed under
	// each of them: a mount is encrypted only if every path to it is.
	state := map[string]bool{}
	var walk func(d lsblkDevice, encrypted bool, depth int)
	walk = func(d lsblkDevice, encrypted bool, depth int) {
		if depth > lsblkMaxDepth {
			return
		}
		t := strings.ToLower(d.Type)
		if t == "loop" || t == "rom" {
			return
		}
		if t == "crypt" {
			encrypted = true
		}
		var mounts []string
		if d.MountPoint != nil {
			mounts = append(mounts, *d.MountPoint)
		}
		for _, m := range d.MountPoints {
			if m != nil {
				mounts = append(mounts, *m)
			}
		}
		for _, mp := range mounts {
			if skipMount(mp) {
				continue
			}
			if prev, seen := state[mp]; seen {
				state[mp] = prev && encrypted
			} else {
				state[mp] = encrypted
			}
		}
		for _, c := range d.Children {
			walk(c, encrypted, depth+1)
		}
	}
	for _, d := range r.BlockDevices {
		walk(d, false, 0)
	}
	if _, ok := state["/"]; !ok {
		return nil, Unsupportedf("the root file system is not on a block device listed by lsblk (container, ZFS or network root)")
	}
	out := make([]protocol.DiskEncryption, 0, len(state))
	for mp, enc := range state {
		v := protocol.DiskEncryption{Volume: mp, Method: MethodNone, Status: StatusDecrypted}
		if enc {
			v.Method, v.Status = MethodLUKS, StatusEncrypted
		}
		out = append(out, v)
	}
	sortVolumes(out)
	return out, nil
}

func sortVolumes(v []protocol.DiskEncryption) {
	sort.Slice(v, func(i, j int) bool { return v[i].Volume < v[j].Volume })
}
