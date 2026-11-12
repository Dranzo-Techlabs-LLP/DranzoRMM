package protocol

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNonceStorePruneAndPersist(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "nonces.json")
	s, err := OpenNonceStore(path, clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAndAdd("a", now, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAndAdd("b", now, now.Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAndAdd("a", now, now.Add(10*time.Minute)); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected replay, got %v", err)
	}

	// The file is owner-only.
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if os.PathSeparator == '/' && fi.Mode().Perm() != 0o600 {
		t.Fatalf("nonces.json mode is %v", fi.Mode().Perm())
	}

	// Survives a restart.
	s2, err := OpenNonceStore(path, clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 2 || s2.WasReset() {
		t.Fatalf("after reopen: len=%d reset=%v", s2.Len(), s2.WasReset())
	}
	if err := s2.CheckAndAdd("b", now, now.Add(time.Minute)); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected replay after restart, got %v", err)
	}

	// Entries are pruned once their retention has passed.
	now = now.Add(15 * time.Minute)
	if err := s2.CheckAndAdd("c", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 2 { // "a" pruned; "b" and "c" remain
		t.Fatalf("expected 2 entries after pruning, got %d", s2.Len())
	}
	now = now.Add(time.Hour)
	s3, err := OpenNonceStore(path, clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s3.Len() != 0 {
		t.Fatalf("expected everything pruned on load, got %d", s3.Len())
	}
}

func TestNonceStoreBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s, err := OpenNonceStore(filepath.Join(t.TempDir(), "nonces.json"), clock, 5)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := s.CheckAndAdd(fmt.Sprint("n", i), now, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// Full: fail closed, never evict a live nonce.
	if err := s.CheckAndAdd("overflow", now, now.Add(time.Minute)); !errors.Is(err, ErrNonceStoreFull) {
		t.Fatalf("expected store full, got %v", err)
	}
	if err := s.CheckAndAdd("n0", now, now.Add(time.Minute)); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("live nonce must still be detected, got %v", err)
	}
	// Space returns once entries expire.
	now = now.Add(2 * time.Minute)
	if err := s.CheckAndAdd("later", now, now.Add(time.Minute)); err != nil {
		t.Fatalf("expected room after expiry, got %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d", s.Len())
	}
}

func TestNonceStoreCorruptFileFailsClosed(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "nonces.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenNonceStore(path, clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !s.WasReset() {
		t.Fatal("a corrupt store must be flagged as reset")
	}
	// A command issued before the reset could be a replay: refused.
	if err := s.CheckAndAdd("old", now.Add(-time.Minute), now.Add(4*time.Minute)); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected refusal of a pre-reset command, got %v", err)
	}
	// A command issued after the reset is fine.
	now = now.Add(10 * time.Second)
	if err := s.CheckAndAdd("new", now, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The barrier survives a restart ...
	s2, _ := OpenNonceStore(path, clock, 0)
	if !s2.WasReset() {
		t.Fatal("barrier must be persisted")
	}
	// ... and is dropped once no pre-reset command can still be valid.
	now = now.Add(time.Hour)
	s3, _ := OpenNonceStore(path, clock, 0)
	if s3.WasReset() {
		t.Fatal("barrier should expire")
	}
}
