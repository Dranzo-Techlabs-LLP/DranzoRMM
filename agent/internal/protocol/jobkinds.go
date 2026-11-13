package protocol

import "time"

// Job kinds (PROTOCOL.md section 6.2).
const (
	KindScript            = "script"
	KindInventoryRefresh  = "inventory.refresh"
	KindSoftwareScan      = "software.scan"
	KindSoftwareInstall   = "software.install"
	KindSoftwareUninstall = "software.uninstall"
	KindPackageInstall    = "package.install"
	KindPackageUninstall  = "package.uninstall"
	KindPatchScan         = "patch.scan"
	KindPatchInstall      = "patch.install"
	KindPostureScan       = "posture.scan"
	KindPolicyEvaluate    = "policy.evaluate"
	KindReboot            = "reboot"
	KindFileList          = "file.list"
	KindFileRead          = "file.read"
	KindFileWrite         = "file.write"
	KindMeshInstall       = "mesh.install"
	KindMeshUninstall     = "mesh.uninstall"
	KindAgentConfigure    = "agent.configure"
	KindAgentUninstall    = "agent.uninstall"
	KindNetworkScan       = "network.scan"
	KindNetworkIsolate    = "network.isolate"
	KindNetworkRelease    = "network.release"
	KindNetworkCertReq    = "network.cert.request"
	KindWifiInstall       = "network.wifi.install"
	KindWifiRemove        = "network.wifi.remove"
)

// Job limits (sections 3 and 6.1).
const (
	OutputChunkBytes      = 16 << 10
	DefaultMaxOutputBytes = 1 << 20
	HardMaxOutputBytes    = 16 << 20
	DefaultJobTimeout     = 300
	MaxJobTimeoutSeconds  = 24 * 60 * 60
	DefaultMaxConcurrent  = 4
	DefaultJobQueueSize   = 32
	MaxSoftwareItems      = 5000
)

// Script languages.
const (
	LangPowerShell = "powershell"
	LangCmd        = "cmd"
	LangBash       = "bash"
	LangZsh        = "zsh"
	LangSh         = "sh"
	LangPython     = "python"
)

// RunAs values.
const (
	RunAsSystem = "system"
	RunAsUser   = "user"
)

// ScriptSpec is the spec of the "script" kind.
type ScriptSpec struct {
	Language                string            `json:"language"`
	Body                    string            `json:"body"`
	Args                    []string          `json:"args"`
	Env                     map[string]string `json:"env"`
	RunAs                   string            `json:"runAs"`
	RequireSignedPowerShell bool              `json:"requireSignedPowerShell"`
}

// Software managers.
const (
	ManagerWinget = "winget"
	ManagerBrew   = "brew"
	ManagerApt    = "apt"
	ManagerDnf    = "dnf"
)

// SoftwareSpec is the spec of software.install / software.uninstall.
type SoftwareSpec struct {
	Manager   string `json:"manager"`
	PackageID string `json:"packageId"`
	Version   string `json:"version,omitempty"`
}

// InstallResult is the result of software.* and package.install.
type InstallResult struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
}

// Detection describes how to detect an installed package.
type Detection struct {
	Type       string `json:"type"`
	Key        string `json:"key"`
	ValueName  string `json:"valueName,omitempty"`
	MinVersion string `json:"minVersion,omitempty"`
}

// PackageInstallSpec is the spec of package.install.
type PackageInstallSpec struct {
	BlobID      string     `json:"blobId"`
	SHA256      string     `json:"sha256"`
	SizeBytes   int64      `json:"sizeBytes"`
	FileName    string     `json:"fileName"`
	Type        string     `json:"type"`
	InstallArgs []string   `json:"installArgs"`
	Detection   *Detection `json:"detection,omitempty"`
}

// PackageUninstallSpec is the spec of package.uninstall.
type PackageUninstallSpec struct {
	Type             string     `json:"type"`
	UninstallCommand []string   `json:"uninstallCommand"`
	ProductCode      string     `json:"productCode,omitempty"`
	Detection        *Detection `json:"detection,omitempty"`
}

// PackageUninstallResult is the result of package.uninstall.
type PackageUninstallResult struct {
	Installed bool `json:"installed"`
}

// RebootPolicy is the reboot part of patch.install.
type RebootPolicy struct {
	Mode            string `json:"mode"`
	NotifyUser      bool   `json:"notifyUser"`
	Deferrals       int    `json:"deferrals"`
	DeadlineMinutes int    `json:"deadlineMinutes"`
	Message         string `json:"message"`
}

// PatchInstallSpec is the spec of patch.install. UpdateIDs nil means "all approved".
type PatchInstallSpec struct {
	UpdateIDs []string     `json:"updateIds"`
	Sources   []string     `json:"sources"`
	Reboot    RebootPolicy `json:"reboot"`
}

// PatchInstallItem is one entry of PatchInstallResult.Installed.
type PatchInstallItem struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// PatchInstallResult is the result of patch.install.
type PatchInstallResult struct {
	Installed      []PatchInstallItem `json:"installed"`
	RebootRequired bool               `json:"rebootRequired"`
}

// PolicyCheck is one check of policy.evaluate.
type PolicyCheck struct {
	PolicyID  string         `json:"policyId"`
	Check     string         `json:"check"`
	Params    map[string]any `json:"params"`
	Remediate bool           `json:"remediate"`
}

// PolicyEvaluateSpec is the spec of policy.evaluate.
type PolicyEvaluateSpec struct {
	Checks []PolicyCheck `json:"checks"`
}

// PolicyCheckResult is one entry of PolicyEvaluateResult.Results.
type PolicyCheckResult struct {
	PolicyID   string `json:"policyId"`
	Check      string `json:"check"`
	Compliant  bool   `json:"compliant"`
	Remediated bool   `json:"remediated"`
	Detail     string `json:"detail"`
}

// PolicyEvaluateResult is the result of policy.evaluate.
type PolicyEvaluateResult struct {
	Results []PolicyCheckResult `json:"results"`
}

// RebootSpec is the spec of the "reboot" kind.
type RebootSpec struct {
	DelaySeconds int    `json:"delaySeconds"`
	Message      string `json:"message"`
	NotifyUser   bool   `json:"notifyUser"`
}

// FileListSpec is the spec of file.list.
type FileListSpec struct {
	Path string `json:"path"`
}

// FileEntry is one directory entry in a file.list result.
type FileEntry struct {
	Name       string    `json:"name"`
	IsDir      bool      `json:"isDir"`
	SizeBytes  int64     `json:"sizeBytes"`
	ModifiedAt time.Time `json:"modifiedAt"`
	Mode       string    `json:"mode"`
}

// FileListResult is the result of file.list.
type FileListResult struct {
	Path      string      `json:"path"`
	Entries   []FileEntry `json:"entries"`
	Truncated bool        `json:"truncated"`
}

// FileReadSpec is the spec of file.read.
type FileReadSpec struct {
	Path     string `json:"path"`
	UploadID string `json:"uploadId"`
	MaxBytes int64  `json:"maxBytes"`
}

// FileReadResult is the result of file.read.
type FileReadResult struct {
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

// FileWriteSpec is the spec of file.write.
type FileWriteSpec struct {
	Path      string `json:"path"`
	BlobID    string `json:"blobId"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	Overwrite bool   `json:"overwrite"`
}

// FileWriteResult is the result of file.write.
type FileWriteResult struct {
	SizeBytes int64 `json:"sizeBytes"`
}

// MeshInstallSpec is the spec of mesh.install (mesh.uninstall has an empty spec).
type MeshInstallSpec struct {
	BlobID    string `json:"blobId"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	FileName  string `json:"fileName"`
}

// MeshResult is the result of mesh.install / mesh.uninstall.
type MeshResult struct {
	Installed  bool   `json:"installed"`
	MeshNodeID string `json:"meshNodeId,omitempty"`
}

// UninstallCode is the PBKDF2-HMAC-SHA256 verifier of the technician-set
// uninstall code (salt and hash are standard base64).
type UninstallCode struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Hash       string `json:"hash"`
}

// AgentConfigureSpec is the spec of agent.configure. The uninstallCode key
// distinguishes "absent" (leave unchanged) from "null" (clear), so it is
// decoded by the handler from raw JSON; this struct is the typed form.
type AgentConfigureSpec struct {
	UninstallCode *UninstallCode `json:"uninstallCode"`
}

// NetworkScanSpec is the spec of network.scan.
type NetworkScanSpec struct {
	ResolveNames bool `json:"resolveNames"`
}

// NetworkNeighbor is one device seen on the local network.
type NetworkNeighbor struct {
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	Hostname   string `json:"hostname,omitempty"`
	Gateway    bool   `json:"gateway,omitempty"`
	Randomized bool   `json:"randomized,omitempty"`
}

// NetworkScanResult is the result of network.scan.
type NetworkScanResult struct {
	ScannedAt time.Time         `json:"scannedAt"`
	Subnets   []string          `json:"subnets"`
	Gateway   string            `json:"gateway"`
	Neighbors []NetworkNeighbor `json:"neighbors"`
	Truncated bool              `json:"truncated"`
}

// IsolationEndpoint is a host and port kept reachable while isolated.
type IsolationEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// NetworkIsolateSpec is the spec of network.isolate.
type NetworkIsolateSpec struct {
	Allow   []IsolationEndpoint `json:"allow"`
	Message string              `json:"message"`
}

// NetworkIsolateResult is the result of network.isolate.
type NetworkIsolateResult struct {
	Allowed []string `json:"allowed"`
}

// NetworkReleaseSpec is the spec of network.release.
type NetworkReleaseSpec struct {
	Message string `json:"message"`
}

// NetworkCertResult is the result of network.cert.request.
type NetworkCertResult struct {
	CSR string `json:"csr"`
}

// WifiInstallSpec is the spec of network.wifi.install.
type WifiInstallSpec struct {
	SSID    string `json:"ssid"`
	CAPem   string `json:"caPem"`
	CertPem string `json:"certPem"`
}

// WifiInstallResult is the result of network.wifi.install.
type WifiInstallResult struct {
	Installed bool `json:"installed"`
}

// WifiRemoveSpec is the spec of network.wifi.remove.
type WifiRemoveSpec struct {
	SSID string `json:"ssid"`
}
