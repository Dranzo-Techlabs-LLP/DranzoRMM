package transport

import (
	"math/rand/v2"
	"time"
)

// Reconnect policy (PROTOCOL.md section 3 and 2.3).
const (
	BackoffBase       = 1 * time.Second
	BackoffFactor     = 2
	BackoffCap        = 5 * time.Minute
	BackoffRevokedCap = 1 * time.Hour
	// StableAfter is how long a connection must last to reset the backoff.
	StableAfter = 60 * time.Second
)

// Backoff computes reconnect delays: exponential (base 1 s, factor 2, cap
// 5 min) with full jitter, i.e. a uniformly random delay in [0, ceiling].
type Backoff struct {
	Base time.Duration
	Cap  time.Duration
	// Rand returns a uniformly random int64 in [0, n). Nil uses math/rand/v2
	// (jitter needs no cryptographic randomness).
	Rand    func(n int64) int64
	attempt int
}

// NewBackoff returns the protocol's default policy.
func NewBackoff() *Backoff { return &Backoff{Base: BackoffBase, Cap: BackoffCap} }

// Ceiling returns the un-jittered upper bound for the next attempt under the
// given cap (0 means the configured cap).
func (b *Backoff) Ceiling(limit time.Duration) time.Duration {
	if limit <= 0 {
		limit = b.Cap
	}
	ceiling := b.Base
	for i := 0; i < b.attempt && ceiling < limit; i++ {
		ceiling *= BackoffFactor
	}
	if ceiling > limit {
		ceiling = limit
	}
	return ceiling
}

// Next returns the delay before the next attempt and advances the state.
func (b *Backoff) Next() time.Duration { return b.NextWithCap(0) }

// NextWithCap is Next with an explicit cap (used for the 1 hour cap that
// applies while the device is revoked).
func (b *Backoff) NextWithCap(limit time.Duration) time.Duration {
	ceiling := b.Ceiling(limit)
	if b.attempt < 62 {
		b.attempt++
	}
	if ceiling <= 0 {
		return 0
	}
	rnd := b.Rand
	if rnd == nil {
		rnd = rand.Int64N
	}
	return time.Duration(rnd(int64(ceiling) + 1))
}

// Reset restarts the sequence (after a connection that lasted StableAfter).
func (b *Backoff) Reset() { b.attempt = 0 }

// Attempt returns the number of delays handed out since the last reset.
func (b *Backoff) Attempt() int { return b.attempt }
