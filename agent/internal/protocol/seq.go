package protocol

import (
	"errors"
	"sync"
)

// Errors returned by SeqTracker.
var (
	ErrSessionNotActive = errors.New("session not active")
	ErrBadSeq           = errors.New("sequence number is not last+1")
	ErrSessionIDReused  = errors.New("session id was already used")
)

const maxClosedSessions = 1024

// SeqTracker implements the replay protection of session.input: for every
// active terminal session the sequence number must be exactly last+1, starting
// at 1. Sessions never survive a restart or the loss of the control
// connection, so the tracker is deliberately in-memory only.
type SeqTracker struct {
	mu     sync.Mutex
	last   map[string]uint64
	closed map[string]struct{}
	order  []string
}

// NewSeqTracker returns an empty tracker.
func NewSeqTracker() *SeqTracker {
	return &SeqTracker{last: map[string]uint64{}, closed: map[string]struct{}{}}
}

// Open starts tracking a session that just became active. A session id may be
// opened only once, so input captured from an earlier session with the same
// id can never be replayed into a new one.
func (t *SeqTracker) Open(sessionID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.last[sessionID]; ok {
		return ErrSessionIDReused
	}
	if _, ok := t.closed[sessionID]; ok {
		return ErrSessionIDReused
	}
	t.last[sessionID] = 0
	return nil
}

// Close stops tracking a session; later input for it is refused.
func (t *SeqTracker) Close(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.last[sessionID]; !ok {
		return
	}
	delete(t.last, sessionID)
	t.closed[sessionID] = struct{}{}
	t.order = append(t.order, sessionID)
	for len(t.order) > maxClosedSessions {
		delete(t.closed, t.order[0])
		t.order = t.order[1:]
	}
}

// CloseAll ends every tracked session (used when the control connection drops).
func (t *SeqTracker) CloseAll() {
	t.mu.Lock()
	ids := make([]string, 0, len(t.last))
	for id := range t.last {
		ids = append(ids, id)
	}
	t.mu.Unlock()
	for _, id := range ids {
		t.Close(id)
	}
}

// Accept atomically checks that seq is exactly last+1 for the session and
// advances the counter.
func (t *SeqTracker) Accept(sessionID string, seq uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.last[sessionID]
	if !ok {
		return ErrSessionNotActive
	}
	if seq != last+1 {
		return ErrBadSeq
	}
	t.last[sessionID] = seq
	return nil
}
