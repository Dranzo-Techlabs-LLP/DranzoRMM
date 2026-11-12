package protocol

import (
	"encoding/json"
	"time"
)

// ---- Agent -> server payloads (PROTOCOL.md section 5) ----

// Hello is the first message on every connection.
type Hello struct {
	AgentVersion    string   `json:"agentVersion"`
	ProtocolVersion int      `json:"protocolVersion"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	Hostname        string   `json:"hostname"`
	Capabilities    []string `json:"capabilities"`
	TrustKeyIDs     []string `json:"trustKeyIds"`
}

// Heartbeat is sent every heartbeatSeconds.
type Heartbeat struct {
	Seq            uint64  `json:"seq"`
	UptimeSeconds  uint64  `json:"uptimeSeconds"`
	CPUPercent     float64 `json:"cpuPercent"`
	MemUsedPercent float64 `json:"memUsedPercent"`
	ConsoleUser    string  `json:"consoleUser,omitempty"`
	PendingReboot  bool    `json:"pendingReboot"`
	AgentRSSBytes  uint64  `json:"agentRssBytes"`
}

// JobAck acknowledges (or refuses) a job.dispatch.
type JobAck struct {
	JobRunID string `json:"jobRunId"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// Output stream names for job.output.
const (
	StreamStdout = "stdout"
	StreamStderr = "stderr"
)

// JobOutput is one streamed chunk of job output (at most 16 KiB of text).
type JobOutput struct {
	JobRunID string `json:"jobRunId"`
	Seq      uint64 `json:"seq"`
	Stream   string `json:"stream"`
	Data     string `json:"data"`
}

// Job result statuses.
const (
	StatusSucceeded   = "succeeded"
	StatusFailed      = "failed"
	StatusTimeout     = "timeout"
	StatusCancelled   = "cancelled"
	StatusRejected    = "rejected"
	StatusUnsupported = "unsupported"
)

// JobResult ends a job run. Exactly one is sent per accepted job.
type JobResult struct {
	JobRunID     string    `json:"jobRunId"`
	Status       string    `json:"status"`
	ExitCode     *int      `json:"exitCode,omitempty"`
	Message      string    `json:"message,omitempty"`
	Truncated    bool      `json:"truncated"`
	OutputBytes  int64     `json:"outputBytes"`
	OutputSHA256 string    `json:"outputSha256"`
	StartedAt    time.Time `json:"startedAt"`
	FinishedAt   time.Time `json:"finishedAt"`
	Result       any       `json:"result,omitempty"`
}

// Session states for session.status.
const (
	SessionPendingConsent = "pending_consent"
	SessionActive         = "active"
	SessionDenied         = "denied"
	SessionEnded          = "ended"
	SessionFailed         = "failed"
)

// SessionStatus reports a session state change.
type SessionStatus struct {
	SessionID string `json:"sessionId"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}

// SessionOutput carries terminal bytes (standard base64 in Data).
type SessionOutput struct {
	SessionID string `json:"sessionId"`
	Seq       uint64 `json:"seq"`
	Data      string `json:"data"`
}

// Update states for update.status.
const (
	UpdateDownloading = "downloading"
	UpdateVerifying   = "verifying"
	UpdateInstalled   = "installed"
	UpdateRolledBack  = "rolled_back"
	UpdateFailed      = "failed"
)

// UpdateStatus reports self-update progress.
type UpdateStatus struct {
	Version string `json:"version"`
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
}

// ErrorPayload is the payload of an "error" message in either direction.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	RefID   string `json:"refId,omitempty"`
}

// ---- Server -> agent unsigned payloads (section 6) ----

// HelloAck answers hello. Intervals are clamped by the agent before use.
type HelloAck struct {
	ServerTime               time.Time `json:"serverTime"`
	HeartbeatSeconds         int       `json:"heartbeatSeconds"`
	InventoryIntervalSeconds int       `json:"inventoryIntervalSeconds"`
	SoftwareIntervalSeconds  int       `json:"softwareIntervalSeconds"`
	PostureIntervalSeconds   int       `json:"postureIntervalSeconds"`
	PatchScanIntervalSeconds int       `json:"patchScanIntervalSeconds"`
}

// HeartbeatAck answers heartbeat.
type HeartbeatAck struct {
	ServerTime time.Time `json:"serverTime"`
}

// ---- Signed command payloads (sections 4.1, 6.1 - 6.7) ----

// SignedCommon holds the fields present in every signed payload.
// session.input carries no nonce (it uses sessionId + seq instead).
type SignedCommon struct {
	DeviceID  string    `json:"deviceId"`
	Nonce     string    `json:"nonce,omitempty"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// JobDispatch is the payload of job.dispatch.
type JobDispatch struct {
	SignedCommon
	JobRunID       string          `json:"jobRunId"`
	Kind           string          `json:"kind"`
	TimeoutSeconds int             `json:"timeoutSeconds"`
	MaxOutputBytes int64           `json:"maxOutputBytes"`
	SessionID      *string         `json:"sessionId"`
	Spec           json.RawMessage `json:"spec"`
}

// JobCancel is the payload of job.cancel.
type JobCancel struct {
	SignedCommon
	JobRunID string `json:"jobRunId"`
}

// UpdateAvailable is the payload of update.available.
type UpdateAvailable struct {
	SignedCommon
	Version   string `json:"version"`
	BlobID    string `json:"blobId"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	Ring      string `json:"ring"`
	Force     bool   `json:"force"`
}

// Session kinds and consent modes.
const (
	SessionKindTerminal = "terminal"
	SessionKindFiles    = "files"
	SessionKindDesktop  = "desktop"

	ConsentNone    = "none"
	ConsentNotify  = "notify"
	ConsentRequire = "require"
)

// TerminalOptions are the terminal parameters of session.start.
type TerminalOptions struct {
	Cols  int    `json:"cols"`
	Rows  int    `json:"rows"`
	RunAs string `json:"runAs"`
}

// SessionStart is the payload of session.start.
type SessionStart struct {
	SignedCommon
	SessionID             string           `json:"sessionId"`
	Kind                  string           `json:"kind"`
	Consent               string           `json:"consent"`
	ConsentTimeoutSeconds int              `json:"consentTimeoutSeconds"`
	RequestedBy           string           `json:"requestedBy"`
	Terminal              *TerminalOptions `json:"terminal,omitempty"`
}

// SessionEnd is the payload of session.end.
type SessionEnd struct {
	SignedCommon
	SessionID string `json:"sessionId"`
	Reason    string `json:"reason"`
}

// Session input kinds.
const (
	SessionInputData   = "data"
	SessionInputResize = "resize"
)

// SessionInput is the payload of session.input (no nonce; seq based).
type SessionInput struct {
	DeviceID  string    `json:"deviceId"`
	SessionID string    `json:"sessionId"`
	Seq       uint64    `json:"seq"`
	Kind      string    `json:"kind"`
	Data      string    `json:"data,omitempty"`
	Cols      int       `json:"cols,omitempty"`
	Rows      int       `json:"rows,omitempty"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// CommandKey is one trusted Ed25519 command-signing public key.
type CommandKey struct {
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"publicKey"`
}

// TrustRotate is the payload of trust.rotate.
type TrustRotate struct {
	SignedCommon
	CommandKeys    []CommandKey `json:"commandKeys"`
	CACertificates string       `json:"caCertificates,omitempty"`
}

// ---- Enrollment / renewal (section 2) ----

// EnrollRequest is the body of POST /agent/v1/enroll.
type EnrollRequest struct {
	Token        string `json:"token"`
	CSR          string `json:"csr"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agentVersion"`
	MachineID    string `json:"machineId"`
}

// RenewRequest is the body of POST /agent/v1/renew.
type RenewRequest struct {
	CSR string `json:"csr"`
}

// CertificateResponse is the response of enroll and renew.
type CertificateResponse struct {
	DeviceID       string    `json:"deviceId"`
	Certificate    string    `json:"certificate"`
	CACertificates string    `json:"caCertificates"`
	NotAfter       time.Time `json:"notAfter"`
}

// OS family names used in enroll, hello and inventory.
const (
	OSWindows = "windows"
	OSMacOS   = "macos"
	OSLinux   = "linux"
)
