package protocol

import "time"

// ---- 7.1 inventory ----

// OSInfo describes the operating system.
type OSInfo struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
	Kernel  string `json:"kernel"`
}

// CPUInfo describes the processor.
type CPUInfo struct {
	Model        string `json:"model"`
	Cores        int    `json:"cores"`
	LogicalCores int    `json:"logicalCores"`
}

// DiskInfo is one mounted real filesystem.
type DiskInfo struct {
	Device     string `json:"device"`
	MountPoint string `json:"mountPoint"`
	FSType     string `json:"fsType"`
	TotalBytes uint64 `json:"totalBytes"`
	FreeBytes  uint64 `json:"freeBytes"`
}

// NetworkInterface is one non-loopback network interface.
type NetworkInterface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

// AgentStats are the agent's own resource statistics.
type AgentStats struct {
	Version    string  `json:"version"`
	CPUPercent float64 `json:"cpuPercent"`
	RSSBytes   uint64  `json:"rssBytes"`
}

// Inventory is the payload of the "inventory" message. A sub-section the OS
// cannot provide is null and its name is listed in Unsupported.
type Inventory struct {
	CollectedAt   time.Time          `json:"collectedAt"`
	Hostname      string             `json:"hostname"`
	MachineID     string             `json:"machineId"`
	OS            *OSInfo            `json:"os"`
	Arch          string             `json:"arch"`
	CPU           *CPUInfo           `json:"cpu"`
	MemoryBytes   uint64             `json:"memoryBytes"`
	Disks         []DiskInfo         `json:"disks"`
	Network       []NetworkInterface `json:"network"`
	Serial        string             `json:"serial"`
	Manufacturer  string             `json:"manufacturer"`
	Model         string             `json:"model"`
	ConsoleUser   string             `json:"consoleUser"`
	LoggedInUsers []string           `json:"loggedInUsers"`
	BootTime      *time.Time         `json:"bootTime"`
	UptimeSeconds uint64             `json:"uptimeSeconds"`
	PendingReboot bool               `json:"pendingReboot"`
	Timezone      string             `json:"timezone"`
	Agent         *AgentStats        `json:"agent"`
	Unsupported   []string           `json:"unsupported"`
}

// ---- 7.2 software.inventory ----

// Software sources.
const (
	SourceRegistry = "registry"
	SourceWinget   = "winget"
	SourceApp      = "app"
	SourcePkgutil  = "pkgutil"
	SourceBrew     = "brew"
	SourceDpkg     = "dpkg"
	SourceRPM      = "rpm"
	SourceSnap     = "snap"
	SourceFlatpak  = "flatpak"
)

// SoftwareItem is one installed program.
type SoftwareItem struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher,omitempty"`
	Source      string `json:"source"`
	ID          string `json:"id,omitempty"`
	InstallDate string `json:"installDate,omitempty"`
}

// SoftwareInventory is the payload of "software.inventory" (max 5,000 items).
type SoftwareInventory struct {
	CollectedAt time.Time      `json:"collectedAt"`
	Items       []SoftwareItem `json:"items"`
	Truncated   bool           `json:"truncated"`
	Unsupported []string       `json:"unsupported"`
}

// ---- 7.3 posture ----

// AntivirusProduct is one detected antivirus product.
type AntivirusProduct struct {
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	UpToDate         bool   `json:"upToDate"`
	SignatureVersion string `json:"signatureVersion"`
	Source           string `json:"source"`
}

// FirewallState is the host firewall state.
type FirewallState struct {
	Enabled bool   `json:"enabled"`
	Detail  string `json:"detail"`
}

// DiskEncryption is the encryption state of one volume.
type DiskEncryption struct {
	Volume string `json:"volume"`
	Method string `json:"method"`
	Status string `json:"status"`
}

// ScreenLock is the screen lock configuration.
type ScreenLock struct {
	Enabled        bool `json:"enabled"`
	TimeoutSeconds int  `json:"timeoutSeconds"`
}

// ListeningPort is one listening socket.
type ListeningPort struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process"`
}

// Posture is the payload of the "posture" message.
type Posture struct {
	CollectedAt    time.Time          `json:"collectedAt"`
	Antivirus      []AntivirusProduct `json:"antivirus"`
	Firewall       *FirewallState     `json:"firewall"`
	DiskEncryption []DiskEncryption   `json:"diskEncryption"`
	LocalAdmins    []string           `json:"localAdmins"`
	ScreenLock     *ScreenLock        `json:"screenLock"`
	LastPatchDate  *time.Time         `json:"lastPatchDate"`
	PendingReboot  bool               `json:"pendingReboot"`
	ListeningPorts []ListeningPort    `json:"listeningPorts"`
	Unsupported    []string           `json:"unsupported"`
}

// ---- 7.4 patch.state ----

// PendingPatch is one pending update.
type PendingPatch struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	KB             string `json:"kb,omitempty"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Source         string `json:"source"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	NewVersion     string `json:"newVersion,omitempty"`
	SizeBytes      *int64 `json:"sizeBytes,omitempty"`
	RequiresReboot *bool  `json:"requiresReboot,omitempty"`
}

// PatchState is the payload of the "patch.state" message.
type PatchState struct {
	CollectedAt    time.Time      `json:"collectedAt"`
	Pending        []PendingPatch `json:"pending"`
	RebootRequired bool           `json:"rebootRequired"`
	LastInstallAt  *time.Time     `json:"lastInstallAt,omitempty"`
	ScanError      string         `json:"scanError,omitempty"`
	Unsupported    []string       `json:"unsupported"`
}
