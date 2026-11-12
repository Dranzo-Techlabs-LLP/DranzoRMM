package update

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"time"
)

// GuardOptions configures Guard.
type GuardOptions struct {
	// StateDir is the agent's protected data directory.
	StateDir string
	// MaxRuns is how often the guard may find the same update unconfirmed
	// before it rolls back (zero: DefaultMaxStarts).
	MaxRuns int
	Log     *slog.Logger

	// Seams for tests.
	now         func() time.Time
	checkExe    func(path string) error
	renameAside *bool
	failpoint   func(point string)
}

// Guard is the part of the rollback that does not depend on the new binary.
//
// The watchdog inside the agent can only act if the new version gets as far
// as running it. A binary that dies earlier (it does not load, or crashes
// during initialisation) is restarted by the service manager for ever. Guard
// closes that gap when it is run from the PREVIOUS binary, which is known to
// work, by something other than the new binary:
//
//   - before every start of the service (systemd:
//     "ExecStartPre=-<exe>.previous update-guard"), or
//   - periodically (a launchd daemon with StartInterval, a Windows scheduled
//     task, a systemd timer), followed by a restart of the service when Guard
//     reports a rollback.
//
// Each run that finds the pending version still unconfirmed is counted in
// update-state.json. Once the count exceeds MaxRuns, Guard restores
// <exe>.previous and records the version as failed; the previous version then
// reports "rolled_back" when it connects. Counting runs rather than elapsed
// time means a machine that was switched off or asleep is not mistaken for a
// version that failed.
//
// Guard is not wired to a command by this package: using it needs an
// "update-guard" sub-command in cmd/dranzo-agent and one line in the service
// definition.
func Guard(opts GuardOptions) (rolledBack bool, err error) {
	if opts.StateDir == "" {
		return false, errors.New("update guard: no state directory")
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.MaxRuns <= 0 {
		opts.MaxRuns = DefaultMaxStarts
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.checkExe == nil {
		opts.checkExe = func(path string) error {
			return CheckExecutableFile(path, runtime.GOOS, runtime.GOARCH)
		}
	}
	s := store{dir: opts.StateDir}
	st, err := s.loadState()
	if err != nil || st == nil {
		// Nothing pending (or unreadable state, which the agent discards).
		return false, err
	}
	if st.ExePath == "" || !filepath.IsAbs(st.ExePath) {
		return false, errors.New("update guard: the update state names no executable")
	}
	aside := renameAsideDefault
	if opts.renameAside != nil {
		aside = *opts.renameAside
	}
	files := fileOps{paths: exePaths{exe: st.ExePath}, renameAside: aside, fp: opts.failpoint}

	reason := st.Error
	switch st.Phase {
	case phaseSwapping:
		if st.NoRollback {
			return false, nil
		}
		st.GuardRuns++
		if st.GuardRuns <= opts.MaxRuns {
			return false, s.saveState(st)
		}
		reason = fmt.Sprintf("version %s was still unconfirmed after %d checks by the update guard",
			st.PendingVersion, st.GuardRuns-1)
	case phaseRollingBack:
		// A rollback was interrupted; restoring again is idempotent.
	default:
		return false, nil
	}
	opts.Log.Error("update guard: rolling back",
		slog.String("version", st.PendingVersion), slog.String("previous", st.PreviousVersion), slog.String("reason", reason))
	if err := rollbackFiles(s, files, st, reason, opts.checkExe, opts.now); err != nil {
		return false, err
	}
	return true, nil
}
