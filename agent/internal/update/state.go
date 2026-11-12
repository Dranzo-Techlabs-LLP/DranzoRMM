package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
)

// File names inside the agent's protected state directory.
const (
	stateFileName  = "update-state.json"
	failedFileName = "failed-updates.json"
	stagingDirName = "update-staging"
	stagedFileName = "agent.download"

	maxStateFileBytes = 256 << 10
	maxFailedEntries  = 200
	maxErrorLen       = 512
)

// Phases of an update, as persisted in update-state.json. The file exists
// only while an update is in flight or its outcome is still to be reported.
const (
	// phaseSwapping is written (durably) BEFORE the binary is exchanged and
	// stays until the new version confirmed or was rolled back. Whether the
	// exchange happened is derived from the version of the process that
	// reads the file: equal to pendingVersion means the new binary runs.
	phaseSwapping = "swapping"
	// phaseRollingBack is written before the previous binary is restored.
	phaseRollingBack = "rolling_back"
	// phaseRolledBack: previous binary restored; "rolled_back" to be reported.
	phaseRolledBack = "rolled_back"
	// phaseInstalled: the new version connected; "installed" to be reported.
	phaseInstalled = "installed"
	// phaseFailed: nothing was installed; "failed" to be reported.
	phaseFailed = "failed"
)

// State is the content of update-state.json.
type State struct {
	// PendingVersion is the version being installed.
	PendingVersion string `json:"pendingVersion"`
	// PreviousVersion is the version that was running when the update began
	// (the content of <exe>.previous once the exchange happened).
	PreviousVersion string `json:"previousVersion"`
	// StartedAt is when the exchange of the binary began.
	StartedAt time.Time `json:"startedAt"`
	// Attempt counts the starts of the pending version that did not (yet)
	// lead to a confirmed connection.
	Attempt int `json:"attempt"`
	// Phase is one of the phase constants.
	Phase string `json:"phase"`
	// SHA256 is the signed hash of the pending binary.
	SHA256 string `json:"sha256,omitempty"`
	// ExePath is the executable that is exchanged.
	ExePath string `json:"exePath,omitempty"`
	// Error is the reason of a rollback or failure.
	Error string `json:"error,omitempty"`
	// NoRollback is set when a rollback was needed but impossible (no usable
	// <exe>.previous): the pending version keeps running without a watchdog.
	NoRollback bool `json:"noRollback,omitempty"`
	// GuardRuns counts invocations of the external guard (see Guard) while
	// the pending version was unconfirmed.
	GuardRuns int `json:"guardRuns,omitempty"`
}

// FailedUpdate is one entry of failed-updates.json: a version that was rolled
// back on this device and is never installed again.
type FailedUpdate struct {
	Version  string    `json:"version"`
	SHA256   string    `json:"sha256,omitempty"`
	FailedAt time.Time `json:"failedAt"`
	Error    string    `json:"error,omitempty"`
}

type failedFile struct {
	Failed []FailedUpdate `json:"failed"`
}

// store reads and writes the two state files. Every write is atomic and
// durable (temp file, fsync, rename, fsync of the directory), so a reader
// after a crash sees either the old or the new content.
type store struct {
	dir string
}

func (s store) statePath() string  { return filepath.Join(s.dir, stateFileName) }
func (s store) failedPath() string { return filepath.Join(s.dir, failedFileName) }
func (s store) stagingDir() string { return filepath.Join(s.dir, stagingDirName) }

// loadState returns nil, nil when there is no state file. A file that cannot
// be parsed is reported as an error; the caller discards it.
func (s store) loadState() (*State, error) {
	data, err := fsutil.ReadPrivateFile(s.statePath(), maxStateFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", stateFileName, err)
	}
	if st.PendingVersion == "" || st.Phase == "" {
		return nil, fmt.Errorf("parse %s: incomplete state", stateFileName)
	}
	return &st, nil
}

func (s store) saveState(st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.statePath(), data)
}

func (s store) deleteState() error {
	if err := os.Remove(s.statePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(s.dir)
	return nil
}

// loadFailed returns the list of failed versions. A missing file is an empty
// list. An unreadable file is an error and an empty list: the agent then
// forgets old failures rather than refusing every future update (a version
// that fails again is rolled back and recorded again).
func (s store) loadFailed() ([]FailedUpdate, error) {
	data, err := fsutil.ReadPrivateFile(s.failedPath(), maxStateFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f failedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", failedFileName, err)
	}
	return f.Failed, nil
}

// isFailed reports whether version was rolled back on this device before.
func (s store) isFailed(version string) (bool, error) {
	list, err := s.loadFailed()
	for _, f := range list {
		if SameVersion(f.Version, version) {
			return true, err
		}
	}
	return false, err
}

// recordFailed adds version to failed-updates.json (idempotent).
func (s store) recordFailed(version, sha256Hex, reason string, now time.Time) error {
	list, _ := s.loadFailed()
	for _, f := range list {
		if SameVersion(f.Version, version) {
			return nil
		}
	}
	list = append(list, FailedUpdate{Version: version, SHA256: sha256Hex, FailedAt: now.UTC(), Error: clip(reason)})
	if len(list) > maxFailedEntries {
		list = list[len(list)-maxFailedEntries:]
	}
	data, err := json.MarshalIndent(failedFile{Failed: list}, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.failedPath(), data)
}

func clip(s string) string {
	if len(s) > maxErrorLen {
		return s[:maxErrorLen]
	}
	return s
}
