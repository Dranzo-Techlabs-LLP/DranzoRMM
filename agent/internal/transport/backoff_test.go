package transport

import (
	"testing"
	"time"
)

func TestBackoffExponentialWithCap(t *testing.T) {
	b := NewBackoff()
	b.Rand = func(n int64) int64 { return n - 1 } // always the maximum
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		32 * time.Second, 64 * time.Second, 128 * time.Second, 256 * time.Second,
		5 * time.Minute, 5 * time.Minute, 5 * time.Minute,
	}
	for i, w := range want {
		if got := b.Next(); got != w {
			t.Fatalf("attempt %d: got %v want %v", i, got, w)
		}
	}
	b.Reset()
	if got := b.Next(); got != time.Second {
		t.Fatalf("after reset: %v", got)
	}
}

func TestBackoffFullJitter(t *testing.T) {
	b := NewBackoff()
	// Full jitter: the delay is uniform in [0, ceiling], so 0 is a legal value.
	b.Rand = func(int64) int64 { return 0 }
	for i := 0; i < 5; i++ {
		if got := b.Next(); got != 0 {
			t.Fatalf("expected 0, got %v", got)
		}
	}
	// With the real random source every delay stays within the ceiling.
	b = NewBackoff()
	for i := 0; i < 200; i++ {
		ceiling := b.Ceiling(0)
		if d := b.Next(); d < 0 || d > ceiling {
			t.Fatalf("attempt %d: %v outside [0,%v]", i, d, ceiling)
		}
		if ceiling > BackoffCap {
			t.Fatalf("ceiling %v above cap", ceiling)
		}
	}
	// The random source is asked for a value in [0, ceiling] inclusive.
	b = NewBackoff()
	var asked []int64
	b.Rand = func(n int64) int64 { asked = append(asked, n); return 0 }
	b.Next()
	b.Next()
	if asked[0] != int64(time.Second)+1 || asked[1] != int64(2*time.Second)+1 {
		t.Fatalf("unexpected ranges %v", asked)
	}
}

func TestBackoffRevokedCap(t *testing.T) {
	b := NewBackoff()
	b.Rand = func(n int64) int64 { return n - 1 }
	var last time.Duration
	for i := 0; i < 40; i++ {
		last = b.NextWithCap(BackoffRevokedCap)
	}
	if last != time.Hour {
		t.Fatalf("revoked backoff should reach 1 hour, got %v", last)
	}
	// Back to the normal cap for ordinary failures.
	if got := b.Next(); got != BackoffCap {
		t.Fatalf("got %v", got)
	}
}
