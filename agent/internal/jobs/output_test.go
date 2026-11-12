package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

type sink struct {
	mu     sync.Mutex
	chunks []protocol.JobOutput
	fail   bool
}

func (s *sink) send(_ context.Context, o protocol.JobOutput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("not delivered")
	}
	s.chunks = append(s.chunks, o)
	return nil
}

func (s *sink) all() []protocol.JobOutput {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.JobOutput(nil), s.chunks...)
}

func (s *sink) concat() string {
	var b strings.Builder
	for _, c := range s.all() {
		b.WriteString(c.Data)
	}
	return b.String()
}

func checkInvariants(t *testing.T, s *sink, sum Summary) {
	t.Helper()
	h := sha256.New()
	var total int64
	for i, c := range s.all() {
		if c.Seq != uint64(i+1) {
			t.Fatalf("chunk %d has seq %d", i, c.Seq)
		}
		if len(c.Data) == 0 || len(c.Data) > protocol.OutputChunkBytes {
			t.Fatalf("chunk %d has %d bytes", i, len(c.Data))
		}
		if !utf8.ValidString(c.Data) {
			t.Fatalf("chunk %d is not valid UTF-8", i)
		}
		if c.Stream != protocol.StreamStdout && c.Stream != protocol.StreamStderr {
			t.Fatalf("chunk %d has stream %q", i, c.Stream)
		}
		h.Write([]byte(c.Data))
		total += int64(len(c.Data))
	}
	if sum.OutputBytes != total {
		t.Fatalf("outputBytes %d != delivered %d", sum.OutputBytes, total)
	}
	if got := hex.EncodeToString(h.Sum(nil)); sum.OutputSHA256 != got {
		t.Fatalf("outputSha256 %s != %s", sum.OutputSHA256, got)
	}
	if sum.Chunks != uint64(len(s.all())) {
		t.Fatalf("chunk count %d != %d", sum.Chunks, len(s.all()))
	}
}

func TestOutputChunksOnUTF8Boundaries(t *testing.T) {
	s := &sink{}
	o := NewOutputStream(context.Background(), "job", 1<<20, time.Hour, s.send)
	// 3-byte runes: 16384 is not a multiple of 3, so a naive cut would split a character.
	text := strings.Repeat("€", 20000) // 60,000 bytes
	if _, err := o.Writer(protocol.StreamStdout).Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	sum := o.Close()
	checkInvariants(t, s, sum)
	if s.concat() != text {
		t.Fatal("output was altered")
	}
	chunks := s.all()
	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(chunks))
	}
	if len(chunks[0].Data) != 16383 { // largest multiple of 3 <= 16384
		t.Fatalf("first chunk has %d bytes", len(chunks[0].Data))
	}
	if sum.Truncated {
		t.Fatal("must not be truncated")
	}
}

func TestOutputMultibyteSplitAcrossWrites(t *testing.T) {
	s := &sink{}
	o := NewOutputStream(context.Background(), "job", 1<<20, time.Hour, s.send)
	w := o.Writer(protocol.StreamStdout)
	raw := []byte("héllo wörld 😀 done")
	for _, b := range raw { // worst case: one byte per write
		_, _ = w.Write([]byte{b})
	}
	sum := o.Close()
	checkInvariants(t, s, sum)
	if s.concat() != string(raw) {
		t.Fatalf("got %q", s.concat())
	}
}

func TestOutputInvalidBytesReplaced(t *testing.T) {
	const rep = string(utf8.RuneError)
	s := &sink{}
	o := NewOutputStream(context.Background(), "job", 1<<20, time.Hour, s.send)
	w := o.Writer(protocol.StreamStdout)
	_, _ = w.Write([]byte{'a', 0xff, 'b', 0xc3}) // 0xff invalid, 0xc3 an incomplete lead byte
	_, _ = w.Write([]byte{'c'})                  // ... that is not completed
	_, _ = w.Write([]byte{0xe2, 0x82})           // incomplete at the very end
	sum := o.Close()
	checkInvariants(t, s, sum)
	// Every invalid byte becomes one U+FFFD (the two trailing bytes are an unfinished sequence).
	if got, want := s.concat(), "a"+rep+"b"+rep+"c"+rep+rep; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestOutputCapAndTruncated(t *testing.T) {
	s := &sink{}
	const limit = 40000
	o := NewOutputStream(context.Background(), "job", limit, time.Hour, s.send)
	w := o.Writer(protocol.StreamStdout)
	for i := 0; i < 30; i++ {
		_, _ = w.Write([]byte(strings.Repeat("€", 1000))) // 3000 bytes each, 90,000 total
	}
	// Writes after the cap are swallowed, never an error (the process must not block).
	if n, err := w.Write([]byte("more")); err != nil || n != 4 {
		t.Fatalf("write after cap: n=%d err=%v", n, err)
	}
	sum := o.Close()
	checkInvariants(t, s, sum)
	if !sum.Truncated {
		t.Fatal("truncated flag not set")
	}
	if sum.OutputBytes > limit || sum.OutputBytes < limit-3 {
		t.Fatalf("delivered %d bytes with a cap of %d", sum.OutputBytes, limit)
	}
	if sum.OutputBytes != 39999 { // largest multiple of 3 <= 40000: the cut respects rune boundaries
		t.Fatalf("delivered %d bytes", sum.OutputBytes)
	}
}

func TestOutputExactCapIsNotTruncated(t *testing.T) {
	s := &sink{}
	o := NewOutputStream(context.Background(), "job", 10, time.Hour, s.send)
	_, _ = o.Writer(protocol.StreamStdout).Write([]byte("0123456789"))
	sum := o.Close()
	checkInvariants(t, s, sum)
	if sum.Truncated || sum.OutputBytes != 10 {
		t.Fatalf("%+v", sum)
	}
}

func TestOutputStreamsKeepOrder(t *testing.T) {
	s := &sink{}
	o := NewOutputStream(context.Background(), "job", 1<<20, time.Hour, s.send)
	out, errw := o.Writer(protocol.StreamStdout), o.Writer(protocol.StreamStderr)
	_, _ = out.Write([]byte("one "))
	_, _ = out.Write([]byte("two"))
	_, _ = errw.Write([]byte("oops"))
	_, _ = out.Write([]byte("three"))
	sum := o.Close()
	checkInvariants(t, s, sum)
	chunks := s.all()
	if len(chunks) != 3 || chunks[0].Data != "one two" || chunks[0].Stream != "stdout" ||
		chunks[1].Data != "oops" || chunks[1].Stream != "stderr" || chunks[2].Data != "three" {
		t.Fatalf("unexpected chunks: %+v", chunks)
	}
}

func TestOutputPeriodicFlush(t *testing.T) {
	s := &sink{}
	o := NewOutputStream(context.Background(), "job", 1<<20, 20*time.Millisecond, s.send)
	_, _ = o.Writer(protocol.StreamStdout).Write([]byte("partial line"))
	deadline := time.Now().Add(2 * time.Second)
	for len(s.all()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.concat(); got != "partial line" {
		t.Fatalf("not flushed by the timer: %q", got)
	}
	checkInvariants(t, s, o.Close())
}

func TestOutputEmpty(t *testing.T) {
	s := &sink{}
	sum := NewOutputStream(context.Background(), "job", 0, time.Hour, s.send).Close()
	if sum.OutputBytes != 0 || sum.Truncated || sum.OutputSHA256 != emptySHA256 {
		t.Fatalf("%+v", sum)
	}
}

func TestOutputUndeliveredChunkIsNotCounted(t *testing.T) {
	s := &sink{}
	o := NewOutputStream(context.Background(), "job", 1<<20, time.Hour, s.send)
	w := o.Writer(protocol.StreamStdout)
	_, _ = w.Write(bytes.Repeat([]byte("a"), protocol.OutputChunkBytes)) // delivered
	s.mu.Lock()
	s.fail = true
	s.mu.Unlock()
	_, _ = w.Write(bytes.Repeat([]byte("b"), protocol.OutputChunkBytes)) // lost
	sum := o.Close()
	checkInvariants(t, s, sum)
	if sum.OutputBytes != protocol.OutputChunkBytes || !sum.Truncated {
		t.Fatalf("%+v", sum)
	}
}
