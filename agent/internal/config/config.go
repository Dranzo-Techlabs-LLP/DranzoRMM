package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

const maxConfigBytes = 1 << 20

// Interval defaults and clamps (PROTOCOL.md section 6, hello.ack).
const (
	DefaultHeartbeatSeconds = 60
	MinHeartbeatSeconds     = 15
	MaxHeartbeatSeconds     = 600

	MinReportSeconds = 5 * 60
	MaxReportSeconds = 7 * 24 * 60 * 60

	DefaultInventorySeconds = 6 * 60 * 60
	DefaultSoftwareSeconds  = 24 * 60 * 60
	DefaultPostureSeconds   = 60 * 60
	DefaultPatchScanSeconds = 12 * 60 * 60

	MaxConcurrentJobsLimit = 16
)

// Config is config.json.
type Config struct {
	ServerURL                string                  `json:"serverUrl"`
	DeviceID                 string                  `json:"deviceId"`
	HeartbeatSeconds         int                     `json:"heartbeatSeconds"`
	InventoryIntervalSeconds int                     `json:"inventoryIntervalSeconds"`
	SoftwareIntervalSeconds  int                     `json:"softwareIntervalSeconds"`
	PostureIntervalSeconds   int                     `json:"postureIntervalSeconds"`
	PatchScanIntervalSeconds int                     `json:"patchScanIntervalSeconds"`
	MaxConcurrentJobs        int                     `json:"maxConcurrentJobs"`
	UninstallCode            *protocol.UninstallCode `json:"uninstallCode,omitempty"`
}

// Bootstrap is bootstrap.json. Token is erased after a successful enrollment.
type Bootstrap struct {
	ServerURL string `json:"serverUrl"`
	Token     string `json:"token,omitempty"`
}

// Status is the status file written by the running agent.
type Status struct {
	PID        int       `json:"pid"`
	Version    string    `json:"version"`
	Connected  bool      `json:"connected"`
	Since      time.Time `json:"since"`
	LastError  string    `json:"lastError,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt"`
	CertExpiry time.Time `json:"certExpiry,omitempty"`
}

// Clamp forces v into [lo, hi]; zero or negative values become def.
func Clamp(v, lo, hi, def int) int {
	if v <= 0 {
		v = def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Normalize applies defaults and safe ranges to every tunable.
func (c *Config) Normalize() {
	c.HeartbeatSeconds = Clamp(c.HeartbeatSeconds, MinHeartbeatSeconds, MaxHeartbeatSeconds, DefaultHeartbeatSeconds)
	c.InventoryIntervalSeconds = Clamp(c.InventoryIntervalSeconds, MinReportSeconds, MaxReportSeconds, DefaultInventorySeconds)
	c.SoftwareIntervalSeconds = Clamp(c.SoftwareIntervalSeconds, MinReportSeconds, MaxReportSeconds, DefaultSoftwareSeconds)
	c.PostureIntervalSeconds = Clamp(c.PostureIntervalSeconds, MinReportSeconds, MaxReportSeconds, DefaultPostureSeconds)
	c.PatchScanIntervalSeconds = Clamp(c.PatchScanIntervalSeconds, MinReportSeconds, MaxReportSeconds, DefaultPatchScanSeconds)
	c.MaxConcurrentJobs = Clamp(c.MaxConcurrentJobs, 1, MaxConcurrentJobsLimit, protocol.DefaultMaxConcurrent)
}

// ApplyHelloAck clamps and stores the intervals announced by the server and
// reports whether anything changed. Missing (zero) values keep the current setting.
func (c *Config) ApplyHelloAck(ack protocol.HelloAck) bool {
	before := *c
	c.HeartbeatSeconds = Clamp(ack.HeartbeatSeconds, MinHeartbeatSeconds, MaxHeartbeatSeconds, c.HeartbeatSeconds)
	c.InventoryIntervalSeconds = Clamp(ack.InventoryIntervalSeconds, MinReportSeconds, MaxReportSeconds, c.InventoryIntervalSeconds)
	c.SoftwareIntervalSeconds = Clamp(ack.SoftwareIntervalSeconds, MinReportSeconds, MaxReportSeconds, c.SoftwareIntervalSeconds)
	c.PostureIntervalSeconds = Clamp(ack.PostureIntervalSeconds, MinReportSeconds, MaxReportSeconds, c.PostureIntervalSeconds)
	c.PatchScanIntervalSeconds = Clamp(ack.PatchScanIntervalSeconds, MinReportSeconds, MaxReportSeconds, c.PatchScanIntervalSeconds)
	c.Normalize()
	return before.HeartbeatSeconds != c.HeartbeatSeconds ||
		before.InventoryIntervalSeconds != c.InventoryIntervalSeconds ||
		before.SoftwareIntervalSeconds != c.SoftwareIntervalSeconds ||
		before.PostureIntervalSeconds != c.PostureIntervalSeconds ||
		before.PatchScanIntervalSeconds != c.PatchScanIntervalSeconds
}

// ValidateServerURL checks that raw is an https origin (scheme, host, optional
// port; no credentials, path, query or fragment) and returns it normalised.
func ValidateServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 {
		return "", errors.New("server URL is empty or too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("server URL is not valid: %w", err)
	}
	if u.Scheme != "https" {
		return "", errors.New("server URL must use https")
	}
	if u.Hostname() == "" {
		return "", errors.New("server URL has no host")
	}
	if u.User != nil {
		return "", errors.New("server URL must not contain credentials")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("server URL must not contain a path, query or fragment")
	}
	return "https://" + u.Host, nil
}

func loadJSON(path string, v any) error {
	data, err := fsutil.ReadPrivateFile(path, maxConfigBytes)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func saveJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'))
}

// Load reads config.json. A missing file yields os.ErrNotExist.
func Load(p Paths) (*Config, error) {
	var c Config
	if err := loadJSON(p.ConfigFile(), &c); err != nil {
		return nil, err
	}
	if c.ServerURL != "" {
		u, err := ValidateServerURL(c.ServerURL)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.ConfigFile(), err)
		}
		c.ServerURL = u
	}
	if c.DeviceID != "" && !protocol.ValidUUID(c.DeviceID) {
		return nil, fmt.Errorf("%s: deviceId is not a UUID", p.ConfigFile())
	}
	c.Normalize()
	return &c, nil
}

// Save writes config.json atomically with restrictive permissions.
func Save(p Paths, c *Config) error { return saveJSON(p.ConfigFile(), c) }

// LoadBootstrap reads bootstrap.json. A missing file yields os.ErrNotExist.
func LoadBootstrap(p Paths) (*Bootstrap, error) {
	var b Bootstrap
	if err := loadJSON(p.BootstrapFile(), &b); err != nil {
		return nil, err
	}
	u, err := ValidateServerURL(b.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.BootstrapFile(), err)
	}
	b.ServerURL = u
	if len(b.Token) > 512 {
		return nil, fmt.Errorf("%s: token too long", p.BootstrapFile())
	}
	return &b, nil
}

// SaveBootstrap writes bootstrap.json atomically with restrictive permissions.
func SaveBootstrap(p Paths, b *Bootstrap) error { return saveJSON(p.BootstrapFile(), b) }

// EraseToken rewrites bootstrap.json without the enrollment token.
func EraseToken(p Paths) error {
	b, err := LoadBootstrap(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if b.Token == "" {
		return nil
	}
	b.Token = ""
	return SaveBootstrap(p, b)
}

// LoadStatus reads the status file.
func LoadStatus(p Paths) (*Status, error) {
	data, err := fsutil.ReadFileLimited(p.StatusFile(), maxConfigBytes)
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// SaveStatus writes the status file.
func SaveStatus(p Paths, s *Status) error { return saveJSON(p.StatusFile(), s) }
