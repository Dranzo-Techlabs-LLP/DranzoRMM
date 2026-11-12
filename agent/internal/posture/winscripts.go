package posture

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// The PowerShell scripts below are constants. Nothing is ever formatted into
// them. They are fed to "powershell.exe -Command -" on stdin, which executes
// input like an interactive prompt: every line must be one complete
// statement (a block that spans lines would wait for more input), and an
// error in one line does not stop the following lines. Each script therefore
// catches its own errors and always prints exactly one JSON object.
//
// The scripts only read state (Get-* cmdlets, read-only CIM queries).

// psPrelude makes the output UTF-8 and errors catchable.
const psPrelude = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n" +
	"$ErrorActionPreference='Stop'\n" +
	"$ProgressPreference='SilentlyContinue'\n"

// PSAntivirus reads Windows Security Center (client editions) and Microsoft
// Defender (all editions with Defender, including Server).
const PSAntivirus = psPrelude +
	"$r=@{wsc=$null;wscError='';defender=$null;defenderError=''}\n" +
	"try{$r.wsc=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct|ForEach-Object{@{displayName=[string]$_.displayName;productState=[int64]$_.productState}})}catch{$r.wscError=[string]$_.Exception.Message}\n" +
	"try{$m=Get-MpComputerStatus;$u='';if($m.AntivirusSignatureLastUpdated){$u=$m.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')};$r.defender=@{antivirusEnabled=[bool]$m.AntivirusEnabled;realTimeProtectionEnabled=[bool]$m.RealTimeProtectionEnabled;signatureVersion=[string]$m.AntivirusSignatureVersion;signatureLastUpdated=$u;runningMode=[string]$m.AMRunningMode}}catch{$r.defenderError=[string]$_.Exception.Message}\n" +
	"$r|ConvertTo-Json -Compress -Depth 4\n"

// PSFirewall reads the effective Windows Firewall profiles (ActiveStore:
// local settings merged with Group Policy), the categories of the connected
// networks and third-party firewalls registered with Security Center.
const PSFirewall = psPrelude +
	"$r=@{profiles=$null;active=@();products=@();error=''}\n" +
	"try{$r.profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore|ForEach-Object{@{name=[string]$_.Name;enabled=($_.Enabled.ToString() -eq 'True')}})}catch{$r.error=[string]$_.Exception.Message}\n" +
	"try{$r.active=@(Get-NetConnectionProfile|ForEach-Object{[string]$_.NetworkCategory})}catch{}\n" +
	"try{$r.products=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct|ForEach-Object{@{displayName=[string]$_.displayName;productState=[int64]$_.productState}})}catch{}\n" +
	"$r|ConvertTo-Json -Compress -Depth 4\n"

// PSBitLocker reads the BitLocker state of every volume; if the BitLocker
// cmdlets are missing it falls back to the text output of manage-bde.
const PSBitLocker = psPrelude +
	"$r=@{volumes=$null;error='';manageBde=''}\n" +
	"$t=@{}\n" +
	"try{Get-Volume|Where-Object{$_.DriveLetter}|ForEach-Object{$t[([string]$_.DriveLetter)+':']=[string]$_.DriveType}}catch{}\n" +
	"try{$r.volumes=@(Get-BitLockerVolume|ForEach-Object{@{mountPoint=[string]$_.MountPoint;volumeType=[string]$_.VolumeType;volumeStatus=[string]$_.VolumeStatus;protectionStatus=[string]$_.ProtectionStatus;encryptionPercentage=[int]$_.EncryptionPercentage;driveType=[string]$t[[string]$_.MountPoint]}})}catch{$r.error=[string]$_.Exception.Message}\n" +
	"if($null -eq $r.volumes){try{$r.manageBde=[string]((& \"$env:SystemRoot\\System32\\manage-bde.exe\" -status) -join \"`n\")}catch{$r.error=$r.error+'; '+[string]$_.Exception.Message}}\n" +
	"$r|ConvertTo-Json -Compress -Depth 4\n"

// PSLocalAdmins lists the members of the local Administrators group by its
// well-known SID (the group name is localised). Get-LocalGroupMember fails
// when the group contains an orphaned SID, so "net localgroup" is the fallback.
const PSLocalAdmins = psPrelude +
	"$r=@{computer=[string]$env:COMPUTERNAME;members=$null;error='';netOutput='';builtinAdmin=''}\n" +
	"try{$r.members=@(Get-LocalGroupMember -SID 'S-1-5-32-544'|ForEach-Object{@{name=[string]$_.Name;sid=[string]$_.SID.Value;objectClass=[string]$_.ObjectClass;source=[string]$_.PrincipalSource}})}catch{$r.error=[string]$_.Exception.Message}\n" +
	"try{$r.builtinAdmin=[string](Get-LocalUser|Where-Object{$_.SID.Value -like 'S-1-5-21-*-500'}|Select-Object -First 1).Name}catch{}\n" +
	"if($null -eq $r.members){try{$g=(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\\')[-1];$r.netOutput=[string]((& \"$env:SystemRoot\\System32\\net.exe\" localgroup $g) -join \"`n\")}catch{$r.error=$r.error+'; '+[string]$_.Exception.Message}}\n" +
	"$r|ConvertTo-Json -Compress -Depth 4\n"

// PSLastPatch reads the newest hotfix date and the newest successful
// installation in the Windows Update history (antimalware definition updates
// are skipped: they arrive daily and are not patches).
const PSLastPatch = psPrelude +
	"$r=@{hotfix='';wua='';error=''}\n" +
	"try{$h=Get-HotFix|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1;if($h){$r.hotfix=$h.InstalledOn.ToUniversalTime().ToString('o')}}catch{$r.error=[string]$_.Exception.Message}\n" +
	"try{$s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher();$n=$s.GetTotalHistoryCount();if($n -gt 0){$e=$s.QueryHistory(0,[Math]::Min($n,200))|Where-Object{$_.Operation -eq 1 -and $_.ResultCode -eq 2 -and $_.Title -notmatch 'KB2267602|Security Intelligence Update|Definition Update'}|Sort-Object Date -Descending|Select-Object -First 1;if($e){$r.wua=([DateTime]::SpecifyKind($e.Date,[DateTimeKind]::Utc)).ToString('o')}}}catch{$r.error=$r.error+'; '+[string]$_.Exception.Message}\n" +
	"$r|ConvertTo-Json -Compress\n"

// ExtractJSON returns the JSON document printed by a script. It tolerates a
// byte order mark and stray lines around the document.
func ExtractJSON(out string) ([]byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(out, "\xEF\xBB\xBF"))
	if s == "" {
		return nil, errors.New("no output")
	}
	if json.Valid([]byte(s)) && (s[0] == '{' || s[0] == '[') {
		return []byte(s), nil
	}
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(strings.TrimPrefix(lines[i], "\xEF\xBB\xBF"))
		if line == "" || (line[0] != '{' && line[0] != '[') {
			continue
		}
		if json.Valid([]byte(line)) {
			return []byte(line), nil
		}
	}
	return nil, errors.New("output is not JSON")
}

// list decodes a JSON array, and also the single object Windows PowerShell
// prints for a one-element pipeline. Set is false for null or absent.
type list[T any] struct {
	Set   bool
	Items []T
}

// UnmarshalJSON implements json.Unmarshaler.
func (l *list[T]) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	l.Set = true
	if b[0] == '[' {
		return json.Unmarshal(b, &l.Items)
	}
	var one T
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	l.Items = []T{one}
	return nil
}
