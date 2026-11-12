package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// DefaultFlushInterval is how often buffered output is sent.
const DefaultFlushInterval = 250 * time.Millisecond

// OutputSink delivers one job.output chunk. It may block (back-pressure).
type OutputSink func(ctx context.Context, out protocol.JobOutput) error

// OutputStream turns the raw stdout/stderr bytes of a job into job.output
// chunks exactly as PROTOCOL.md defines them:
//
//   - data is valid UTF-8 (invalid bytes become U+FFFD; a multi-byte
//     character is never split across chunks);
//   - a chunk carries at most 16 KiB of text;
//   - buffered output is flushed every ~250 ms;
//   - at most maxBytes bytes are delivered per run, then Truncated is set and
//     further output is discarded;
//   - OutputBytes / OutputSHA256 cover the concatenated data of all delivered
//     chunks in seq order (seq starts at 1).
type OutputStream struct {
	ctx      context.Context
	jobRunID string
	send     OutputSink
	max      int64
	chunk    int

	mu        sync.Mutex
	seq       uint64
	total     int64
	hash      hash.Hash
	truncated bool
	closed    bool
	cur       string
	pending   []byte
	carry     map[string][]byte

	stop chan struct{}
	done chan struct{}
}

// NewOutputStream creates a stream. ctx bounds delivery (not the job itself,
// so the tail of a timed-out job is still delivered).
func NewOutputStream(ctx context.Context, jobRunID string, maxBytes int64, flushEvery time.Duration, send OutputSink) *OutputStream {
	if maxBytes <= 0 {
		maxBytes = protocol.DefaultMaxOutputBytes
	}
	if maxBytes > protocol.HardMaxOutputBytes {
		maxBytes = protocol.HardMaxOutputBytes
	}
	if flushEvery <= 0 {
		flushEvery = DefaultFlushInterval
	}
	o := &OutputStream{
		ctx:      ctx,
		jobRunID: jobRunID,
		send:     send,
		max:      maxBytes,
		chunk:    protocol.OutputChunkBytes,
		hash:     sha256.New(),
		carry:    map[string][]byte{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go o.flushLoop(flushEvery)
	return o
}

func (o *OutputStream) flushLoop(every time.Duration) {
	defer close(o.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-o.stop:
			return
		case <-t.C:
			o.mu.Lock()
			o.flushLocked()
			o.mu.Unlock()
		}
	}
}

type streamWriter struct {
	o      *OutputStream
	stream string
}

func (w streamWriter) Write(p []byte) (int, error) { return w.o.write(w.stream, p) }

// Writer returns the io.Writer for one stream ("stdout" or "stderr").
func (o *OutputStream) Writer(stream string) io.Writer { return streamWriter{o: o, stream: stream} }

// sanitize appends the valid-UTF-8 form of data to dst. Invalid bytes become
// U+FFFD. Unless final, an incomplete multi-byte sequence at the very end is
// returned as rest so it can be completed by the next write.
func sanitize(dst, data []byte, final bool) (out, rest []byte) {
	for len(data) > 0 {
		if data[0] < utf8.RuneSelf {
			dst = append(dst, data[0])
			data = data[1:]
			continue
		}
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			if !final && !utf8.FullRune(data) {
				return dst, append([]byte(nil), data...)
			}
			dst = utf8.AppendRune(dst, utf8.RuneError)
			data = data[1:]
			continue
		}
		dst = append(dst, data[:size]...)
		data = data[size:]
	}
	return dst, nil
}

// cutPoint returns the largest n <= limit such that text[:n] ends on a rune boundary.
func cutPoint(text []byte, limit int) int {
	if len(text) <= limit {
		return len(text)
	}
	n := limit
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return n
}

func (o *OutputStream) write(stream string, p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.truncated {
		// Keep draining the process so it never blocks on a full pipe.
		return len(p), nil
	}
	if stream != o.cur && len(o.pending) > 0 {
		o.flushLocked()
	}
	o.cur = stream
	data := p
	if c := o.carry[stream]; len(c) > 0 {
		data = append(c, p...)
		delete(o.carry, stream)
	}
	var rest []byte
	o.pending, rest = sanitize(o.pending, data, false)
	if len(rest) > 0 {
		o.carry[stream] = rest
	}
	for len(o.pending) >= o.chunk && !o.truncated {
		o.emitLocked(cutPoint(o.pending, o.chunk))
	}
	return len(p), nil
}

// flushLocked sends everything pending for the current stream.
func (o *OutputStream) flushLocked() {
	for len(o.pending) > 0 && !o.truncated {
		o.emitLocked(cutPoint(o.pending, o.chunk))
	}
	o.pending = o.pending[:0]
}

// emitLocked delivers pending[:n] as one chunk, applying the per-run cap.
func (o *OutputStream) emitLocked(n int) {
	if n <= 0 {
		// Cannot happen (a rune is at most 4 bytes, the chunk is 16 KiB), but never loop forever.
		o.pending = o.pending[:0]
		return
	}
	chunk := o.pending[:n]
	if remaining := o.max - o.total; int64(len(chunk)) > remaining {
		chunk = chunk[:cutPoint(chunk, int(remaining))]
		o.truncated = true
	}
	if len(chunk) > 0 {
		out := protocol.JobOutput{JobRunID: o.jobRunID, Seq: o.seq + 1, Stream: o.cur, Data: string(chunk)}
		if err := o.send(o.ctx, out); err != nil {
			// Not delivered: it is not counted, and the output is incomplete.
			o.truncated = true
		} else {
			o.seq++
			o.total += int64(len(chunk))
			_, _ = o.hash.Write(chunk)
		}
	}
	o.pending = append(o.pending[:0], o.pending[n:]...)
	if o.truncated {
		o.pending = o.pending[:0]
	}
}

// Summary describes everything that was delivered.
type Summary struct {
	OutputBytes  int64
	OutputSHA256 string
	Truncated    bool
	Chunks       uint64
}

// Close flushes the remaining output (incomplete trailing bytes are replaced
// by U+FFFD) and returns the totals for job.result. Later writes are discarded.
func (o *OutputStream) Close() Summary {
	close(o.stop)
	<-o.done
	o.mu.Lock()
	defer o.mu.Unlock()
	o.flushLocked()
	for _, stream := range []string{protocol.StreamStdout, protocol.StreamStderr} {
		c := o.carry[stream]
		if len(c) == 0 || o.truncated {
			continue
		}
		o.cur = stream
		o.pending, _ = sanitize(o.pending[:0], c, true)
		o.flushLocked()
	}
	o.carry = map[string][]byte{}
	o.closed = true
	return Summary{
		OutputBytes:  o.total,
		OutputSHA256: hex.EncodeToString(o.hash.Sum(nil)),
		Truncated:    o.truncated,
		Chunks:       o.seq,
	}
}
