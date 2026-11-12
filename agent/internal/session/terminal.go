package session

import (
	"context"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/jobs"
	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// Output and input limits of a terminal session.
const (
	// MaxOutputChunk is the largest number of terminal bytes in one
	// session.output message.
	MaxOutputChunk = 32 << 10
	// MaxInputBytes is the largest decoded session.input data accepted.
	MaxInputBytes = 256 << 10
	// inputQueue is how many inputs may wait for a shell that is not reading.
	inputQueue = 32
	// readQueue is how many PTY reads may wait for the sender. Together with
	// the blocking sender this is the back-pressure: when the server (or the
	// network) is slower than the shell, the shell blocks on its terminal
	// instead of the agent buffering without bound.
	readQueue = 4
)

// TerminalSpec describes the shell to start.
type TerminalSpec struct {
	Cols int
	Rows int
	// AsUser runs the shell as that user (the logged-in console user); nil
	// runs it as the agent itself (root / LocalSystem).
	AsUser *platform.User
}

// Terminal is a shell attached to a pseudo-terminal (a PTY on Unix, a ConPTY
// on Windows). It is a new terminal for the technician: it is not attached
// to, and cannot observe, any terminal or desktop of the logged-in user.
type Terminal interface {
	// Read returns terminal output; it fails once the terminal is gone.
	io.Reader
	// Write sends input (keystrokes) to the shell.
	io.Writer
	// Resize changes the window size.
	Resize(cols, rows int) error
	// Done is closed when the shell process has exited.
	Done() <-chan struct{}
	// Kill terminates the shell and every process started from it.
	Kill()
	// Close releases the pseudo-terminal. Call after Kill.
	Close() error
	// PID is the process id of the process started on the terminal.
	PID() int
}

// StartTerminalFunc starts a shell on a new pseudo-terminal.
type StartTerminalFunc func(ctx context.Context, spec TerminalSpec) (Terminal, error)

// errUnsupported marks something the OS cannot do; the session then fails
// with "not supported on this OS: ...".
type unsupportedError struct{ what string }

func (e *unsupportedError) Error() string { return "not supported on this OS: " + e.what }

// pump streams terminal output as session.output messages: chunks of at most
// MaxOutputChunk bytes, sequence numbers from 1, output coalesced for
// flushEvery so that single keystroke echoes do not become a message each.
type pump struct {
	sessionID  string
	send       jobs.Sender
	flushEvery time.Duration

	chunks chan []byte
	// abort makes the reader discard instead of queue (the session is over).
	abort     chan struct{}
	abortOnce sync.Once
	// readerDone / senderDone are closed when the goroutines have finished.
	readerDone chan struct{}
	senderDone chan struct{}
}

func startPump(sendCtx context.Context, sessionID string, term io.Reader, send jobs.Sender, flushEvery time.Duration) *pump {
	p := &pump{
		sessionID:  sessionID,
		send:       send,
		flushEvery: flushEvery,
		chunks:     make(chan []byte, readQueue),
		abort:      make(chan struct{}),
		readerDone: make(chan struct{}),
		senderDone: make(chan struct{}),
	}
	go p.read(term)
	go p.deliver(sendCtx)
	return p
}

// read copies terminal output into the queue until the terminal is gone. It
// keeps draining after abort so that a closing pseudo-terminal never blocks
// on unread output.
func (p *pump) read(term io.Reader) {
	defer close(p.readerDone)
	defer close(p.chunks)
	buf := make([]byte, MaxOutputChunk)
	aborted := false
	for {
		n, err := term.Read(buf)
		if n > 0 && !aborted {
			chunk := append([]byte(nil), buf[:n]...)
			select {
			case p.chunks <- chunk:
			case <-p.abort:
				aborted = true
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *pump) deliver(ctx context.Context) {
	defer close(p.senderDone)
	// Whatever happens, never leave the reader blocked on the queue.
	defer p.stop()
	var seq uint64
	var pending []byte
	flush := func() bool {
		for len(pending) > 0 {
			n := min(len(pending), MaxOutputChunk)
			seq++
			err := p.send.Send(ctx, protocol.TypeSessionOutput, protocol.SessionOutput{
				SessionID: p.sessionID,
				Seq:       seq,
				Data:      base64.StdEncoding.EncodeToString(pending[:n]),
			})
			if err != nil {
				return false
			}
			pending = pending[n:]
		}
		pending = nil
		return true
	}
	for {
		var chunk []byte
		var ok bool
		select {
		case chunk, ok = <-p.chunks:
		case <-p.abort:
			return
		}
		if !ok {
			return
		}
		pending = append(pending, chunk...)
		closed := false
		timer := time.NewTimer(p.flushEvery)
	coalesce:
		for len(pending) < MaxOutputChunk {
			select {
			case more, ok := <-p.chunks:
				if !ok {
					closed = true
					break coalesce
				}
				pending = append(pending, more...)
			case <-timer.C:
				break coalesce
			case <-p.abort:
				timer.Stop()
				return
			}
		}
		timer.Stop()
		if !flush() || closed {
			return
		}
	}
}

// stop ends the delivery: the sender returns and the reader discards
// whatever the terminal still prints.
func (p *pump) stop() { p.abortOnce.Do(func() { close(p.abort) }) }

// waitDelivered waits until everything read so far was handed to the sender,
// or for at most d.
func (p *pump) waitDelivered(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-p.senderDone:
	case <-t.C:
	}
}
