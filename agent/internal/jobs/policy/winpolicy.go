package policy

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// This file holds the pure parts of the Windows-only checks (parsers,
// decisions, the fixed PowerShell scripts and argument builders) so that
// they are unit-tested on every OS. backend_windows.go only runs them.

// The remediation scripts are constants; nothing is formatted into them. A
// value that varies (the member to remove) is read from an environment
// variable inside the script. Each is one line, because "powershell -Command
// -" executes stdin line by line, and each sets its own exit code.

// PSEnableFirewall turns Windows Firewall on for all three profiles.
const PSEnableFirewall = "try{Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop;exit 0}catch{[Console]::Error.WriteLine([string]$_.Exception.Message);exit 1}\n"

// PSEnableDefender re-enables Microsoft Defender real-time protection with
// the supported cmdlet and starts its service if it is stopped. This is the
// only antivirus remediation of the agent and it only switches protection on.
const PSEnableDefender = "try{Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop;$s=Get-Service -Name WinDefend -ErrorAction Stop;if($s.Status -ne 'Running'){Start-Service -Name WinDefend -ErrorAction Stop};exit 0}catch{[Console]::Error.WriteLine([string]$_.Exception.Message);exit 1}\n"

// EnvAdminMember carries the member (a SID, or a name when no SID is known)
// that PSRemoveAdmin takes out of the Administrators group.
const EnvAdminMember = "DRANZO_ADMIN_MEMBER"

// PSRemoveAdmin removes one member from the local Administrators group
// (well-known SID S-1-5-32-544). The account itself is not touched.
const PSRemoveAdmin = "try{if([string]::IsNullOrEmpty($env:DRANZO_ADMIN_MEMBER)){throw 'no member given'};Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $env:DRANZO_ADMIN_MEMBER -ErrorAction Stop;exit 0}catch{[Console]::Error.WriteLine([string]$_.Exception.Message);exit 1}\n"

// ---- domain controllers ----

// ProductOptionsKey / ProductTypeValue say what kind of Windows this is:
// "WinNT" (workstation), "ServerNT" (member or stand-alone server) or
// "LanmanNT" (domain controller).
const (
	ProductOptionsKey = `SYSTEM\CurrentControlSet\Control\ProductOptions`
	ProductTypeValue  = "ProductType"
)

// IsDomainControllerProductType reports whether the ProductType registry
// value names a domain controller. On a domain controller "net accounts" and
// the Administrators group are the DOMAIN's password policy and built-in
// administrators, not local ones, so the agent never remediates them there.
func IsDomainControllerProductType(productType string) bool {
	return strings.EqualFold(strings.TrimSpace(productType), "LanmanNT")
}

// ---- usb.storage.blocked ----

// USBSTOR start values.
const (
	// USBStorDisabled is the "Start" value that disables the USB
	// mass-storage driver (SERVICE_DISABLED).
	USBStorDisabled = 4
	// USBStorKey and RemovableStorageKey are the registry locations.
	USBStorKey          = `SYSTEM\CurrentControlSet\Services\USBSTOR`
	RemovableStorageKey = `SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices`
	// RemovableDisksClass is the device class of removable disks under
	// RemovableStorageKey.
	RemovableDisksClass = `{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`
)

// usbState is what the registry says about USB mass storage.
type usbState struct {
	// StartKnown / Start: the USBSTOR service start type.
	StartKnown bool
	Start      uint64
	// DenyAll: "All Removable Storage classes: Deny all access" policy.
	DenyAll bool
	// DenyRead / DenyWrite: the removable disks deny policies.
	DenyRead  bool
	DenyWrite bool
}

// evalUSB decides whether USB mass storage is blocked: the USBSTOR driver is
// disabled (Start = 4), or the removable-storage deny policy is set (all
// classes, or removable disks for both read and write).
func evalUSB(s usbState) (blocked bool, detail string) {
	var parts []string
	if s.StartKnown {
		parts = append(parts, fmt.Sprintf("USBSTOR Start=%d", s.Start))
		if s.Start == USBStorDisabled {
			blocked = true
		}
	} else {
		parts = append(parts, "USBSTOR service not present")
	}
	switch {
	case s.DenyAll:
		blocked = true
		parts = append(parts, "removable storage policy: deny all access")
	case s.DenyRead && s.DenyWrite:
		blocked = true
		parts = append(parts, "removable disks policy: deny read and write")
	case s.DenyRead || s.DenyWrite:
		parts = append(parts, "removable disks policy: partial (read and write must both be denied)")
	default:
		parts = append(parts, "no removable storage deny policy")
	}
	return blocked, strings.Join(parts, "; ")
}

// ---- password.policy ----

// PasswordPolicy is the local password policy of a Windows machine.
type PasswordPolicy struct {
	// MinLength is the minimum password length.
	MinLength int
	// MaxAgeDays is the maximum password age; 0 means passwords never expire.
	MaxAgeDays int
	// Complexity is the "password must meet complexity requirements"
	// setting (nil when it could not be read).
	Complexity *bool
}

// netAccountsLabels are the English labels of `net accounts`; the positions
// are the line numbers of the same values in any display language.
const (
	netAccountsMaxAgeLabel = "maximum password age"
	netAccountsMinLenLabel = "minimum password length"
	netAccountsMaxAgeLine  = 2
	netAccountsMinLenLine  = 3
)

// ParseNetAccounts parses `net accounts`:
//
//	Force user logoff how long after time expires?:       Never
//	Minimum password age (days):                          0
//	Maximum password age (days):                          42
//	Minimum password length:                              0
//	Length of password history maintained:                None
//	Lockout threshold:                                    Never
//	...
//
// The English labels are matched first. On another display language the
// values are taken by position (the layout is the same in every language).
// A maximum age that is not a number ("Unlimited") means "never expires".
func ParseNetAccounts(out string) (PasswordPolicy, error) {
	type row struct{ label, value string }
	var rows []row
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		i := strings.LastIndex(line, ":")
		if i <= 0 || i == len(line)-1 {
			continue
		}
		label, value := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		if label == "" || value == "" {
			continue
		}
		rows = append(rows, row{strings.ToLower(label), value})
	}
	maxAge, minLen := "", ""
	for _, r := range rows {
		switch {
		case strings.HasPrefix(r.label, netAccountsMaxAgeLabel):
			maxAge = r.value
		case strings.HasPrefix(r.label, netAccountsMinLenLabel):
			minLen = r.value
		}
	}
	if maxAge == "" || minLen == "" {
		if len(rows) < 9 {
			return PasswordPolicy{}, errors.New("unrecognised `net accounts` output")
		}
		maxAge, minLen = rows[netAccountsMaxAgeLine].value, rows[netAccountsMinLenLine].value
	}
	var p PasswordPolicy
	n, err := strconv.Atoi(minLen)
	if err != nil || n < 0 || n > 256 {
		return PasswordPolicy{}, errors.New("unrecognised minimum password length in `net accounts` output")
	}
	p.MinLength = n
	if n, err := strconv.Atoi(maxAge); err == nil && n > 0 && n <= 99999 {
		p.MaxAgeDays = n
	}
	return p, nil
}

// DecodeSeceditText decodes the file written by `secedit /export` (UTF-16
// little endian with a byte order mark; plain text is passed through).
func DecodeSeceditText(data []byte) string {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		data = data[2:]
		u := make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			u = append(u, uint16(data[i])|uint16(data[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return string(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
}

// ParseSeceditComplexity reads "PasswordComplexity = 0|1" from the [System
// Access] section of a security policy export.
func ParseSeceditComplexity(data []byte) (enabled, ok bool) {
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(DecodeSeceditText(data), "\r", ""), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.ToLower(l)
			continue
		}
		if section != "[system access]" {
			continue
		}
		k, v, found := strings.Cut(l, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "PasswordComplexity") {
			continue
		}
		switch strings.TrimSpace(v) {
		case "1":
			return true, true
		case "0":
			return false, true
		}
	}
	return false, false
}

// netAccountsArgs builds the argv of `net accounts` for the values to set.
// Both are integers that passed validation; nil leaves a value unchanged.
func netAccountsArgs(minLength, maxAgeDays *int) []string {
	args := []string{"accounts"}
	if minLength != nil {
		args = append(args, "/minpwlen:"+strconv.Itoa(*minLength))
	}
	if maxAgeDays != nil {
		args = append(args, "/maxpwage:"+strconv.Itoa(*maxAgeDays))
	}
	return args
}

// passwordWant is the validated params of password.policy.
type passwordWant struct {
	MinLength  *int
	MaxAgeDays *int
	Complexity *bool
}

// passwordGaps compares the current policy with the wanted one. It returns
// the human-readable shortfalls and the values `net accounts` would have to
// set (only ever tightening: a longer minimum, a shorter maximum age).
func passwordGaps(cur PasswordPolicy, want passwordWant) (gaps []string, setMin, setMax *int, complexityGap bool) {
	if want.MinLength != nil && cur.MinLength < *want.MinLength {
		gaps = append(gaps, fmt.Sprintf("minimum length is %d, required %d", cur.MinLength, *want.MinLength))
		setMin = want.MinLength
	}
	if want.MaxAgeDays != nil && (cur.MaxAgeDays == 0 || cur.MaxAgeDays > *want.MaxAgeDays) {
		if cur.MaxAgeDays == 0 {
			gaps = append(gaps, fmt.Sprintf("passwords never expire, required at most %d days", *want.MaxAgeDays))
		} else {
			gaps = append(gaps, fmt.Sprintf("maximum age is %d days, required at most %d", cur.MaxAgeDays, *want.MaxAgeDays))
		}
		setMax = want.MaxAgeDays
	}
	if want.Complexity != nil && *want.Complexity {
		switch {
		case cur.Complexity == nil:
			gaps = append(gaps, "complexity requirement could not be read")
			complexityGap = true
		case !*cur.Complexity:
			gaps = append(gaps, "complexity requirement is off")
			complexityGap = true
		}
	}
	return gaps, setMin, setMax, complexityGap
}

func describePassword(p PasswordPolicy) string {
	age := "never expires"
	if p.MaxAgeDays > 0 {
		age = strconv.Itoa(p.MaxAgeDays) + " days"
	}
	complexity := "unknown"
	if p.Complexity != nil {
		complexity = "off"
		if *p.Complexity {
			complexity = "on"
		}
	}
	return fmt.Sprintf("minimum length %d, maximum age %s, complexity %s", p.MinLength, age, complexity)
}
