package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
)

// Replay-protection errors returned by NonceStore.CheckAndAdd.
var (
	ErrNonceReplayed  = errors.New("nonce already seen")
	ErrNonceStoreFull = errors.New("nonce store is full")
)

const (
	// DefaultMaxNonces bounds the persisted nonce set. Entries live at most
	// ~20 minutes (15 min validity + 5 min retention), so this is far above
	// anything a legitimate server produces.
	DefaultMaxNonces  = 20000
	nonceFileMaxBytes = 8 << 20
	// NonceRetention is how long past expiresAt an accepted nonce is kept.
	NonceRetention = 5 * time.Minute
)

type nonceFile struct {
	Version   int                  `json:"version"`
	NotBefore *time.Time           `json:"notBefore,omitempty"`
	Nonces    map[string]time.Time `json:"nonces"`
}

// NonceStore is the persistent set of accepted command nonces (nonces.json).
// It survives restarts, is pruned by expiry and is bounded in size.
//
// If the file is unreadable or corrupt the store starts empty but records a
// "not before" barrier: commands issued at or before the moment of the reset
// are refused as replays, because the store can no longer prove they were not
// already executed. This fails closed without bricking the agent.
type NonceStore struct {
	mu        sync.Mutex
	path      string
	now       func() time.Time
	max       int
	nonces    map[string]time.Time
	notBefore time.Time
}

// OpenNonceStore loads (or creates) the store at path. now may be nil.
func OpenNonceStore(path string, now func() time.Time, maxEntries int) (*NonceStore, error) {
	if now == nil {
		now = time.Now
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxNonces
	}
	s := &NonceStore{path: path, now: now, max: maxEntries, nonces: map[string]time.Time{}}
	data, err := fsutil.ReadFileLimited(path, nonceFileMaxBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// First start: nothing was ever accepted. The file is still written
		// below so an unwritable data directory is detected at start-up.
	case err == nil:
		var f nonceFile
		if jerr := json.Unmarshal(data, &f); jerr != nil || f.Version != 1 {
			s.notBefore = now().UTC()
			break
		}
		if f.NotBefore != nil {
			s.notBefore = *f.NotBefore
		}
		for n, exp := range f.Nonces {
			s.nonces[n] = exp
		}
	default:
		s.notBefore = now().UTC()
	}
	s.pruneLocked()
	if len(s.nonces) > s.max {
		// A bloated file cannot be trusted to be complete once truncated; reset with a barrier.
		s.nonces = map[string]time.Time{}
		s.notBefore = now().UTC()
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// WasReset reports whether the store had to be reset (corrupt or unreadable
// file) and is therefore refusing commands issued before the reset.
func (s *NonceStore) WasReset() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.notBefore.IsZero()
}

// Len returns the number of stored nonces.
func (s *NonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.nonces)
}

// CheckAndAdd atomically checks that nonce has not been seen and records it
// until keepUntil. The new state is durable on disk before nil is returned, so
// a crash immediately after acceptance cannot enable a replay.
func (s *NonceStore) CheckAndAdd(nonce string, issuedAt, keepUntil time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.notBefore.IsZero() && !issuedAt.After(s.notBefore) {
		return fmt.Errorf("%w: issued before the nonce store was reset", ErrNonceReplayed)
	}
	if _, seen := s.nonces[nonce]; seen {
		return ErrNonceReplayed
	}
	s.pruneLocked()
	if len(s.nonces) >= s.max {
		return ErrNonceStoreFull
	}
	s.nonces[nonce] = keepUntil.UTC()
	if err := s.persistLocked(); err != nil {
		delete(s.nonces, nonce)
		return fmt.Errorf("persist nonce store: %w", err)
	}
	return nil
}

func (s *NonceStore) pruneLocked() {
	now := s.now()
	for n, exp := range s.nonces {
		if exp.Before(now) {
			delete(s.nonces, n)
		}
	}
	// The barrier is only needed while commands issued before it could still
	// be inside their validity window (15 min) plus clock skew (5 min).
	if !s.notBefore.IsZero() && now.Sub(s.notBefore) > MaxValidity+ClockSkew+NonceRetention {
		s.notBefore = time.Time{}
	}
}

func (s *NonceStore) persistLocked() error {
	f := nonceFile{Version: 1, Nonces: s.nonces}
	if !s.notBefore.IsZero() {
		nb := s.notBefore
		f.NotBefore = &nb
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.path, data)
}
