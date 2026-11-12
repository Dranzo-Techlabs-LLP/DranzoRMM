package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/dranzo/dranzormm/agent/internal/protocol"
)

// WSPath is the WebSocket endpoint of the agent listener.
const WSPath = "/agent/v1/ws"

// Defaults for the control connection.
const (
	DefaultSendQueue    = 256
	DefaultPingInterval = 30 * time.Second
	DefaultWriteTimeout = 30 * time.Second
	DefaultDialTimeout  = 45 * time.Second
	// The server allows 50 msg/s (burst 200) and closes the connection with
	// 1008 above that; the writer stays safely below.
	sendRatePerSecond = 40
	sendBurst         = 150
)

// ErrConnClosed is returned by Send/Read once the connection is closed.
var ErrConnClosed = errors.New("connection closed")

// ErrRevoked is reported when the server answers the upgrade with HTTP 403.
var ErrRevoked = errors.New("server refused the device (HTTP 403, revoked)")

// Conn is one established control connection. All writes go through a single
// writer goroutine fed by a bounded queue.
type Conn struct {
	ws     *websocket.Conn
	sendq  chan []byte
	ctx    context.Context
	cancel context.CancelCauseFunc
	wg     sync.WaitGroup

	writeTimeout time.Duration
}

func newConn(parent context.Context, ws *websocket.Conn, queue int, pingEvery, writeTimeout time.Duration) *Conn {
	ctx, cancel := context.WithCancelCause(parent)
	c := &Conn{ws: ws, sendq: make(chan []byte, queue), ctx: ctx, cancel: cancel, writeTimeout: writeTimeout}
	ws.SetReadLimit(protocol.MaxMessageBytes)
	c.wg.Add(2)
	go c.writeLoop()
	go c.pingLoop(pingEvery)
	return c
}

// Done is closed when the connection has failed or was closed.
func (c *Conn) Done() <-chan struct{} { return c.ctx.Done() }

// Err returns why the connection ended (nil while it is open).
func (c *Conn) Err() error { return context.Cause(c.ctx) }

// Send queues one text message. It blocks while the queue is full and returns
// an error if ctx ends or the connection closes first.
func (c *Conn) Send(ctx context.Context, data []byte) error {
	if len(data) > protocol.MaxMessageBytes {
		return fmt.Errorf("message of %d bytes exceeds the protocol limit", len(data))
	}
	select {
	case <-c.ctx.Done():
		return ErrConnClosed
	default:
	}
	select {
	case c.sendq <- data:
		return nil
	case <-c.ctx.Done():
		return ErrConnClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Read returns the next text message (at most 2 MiB).
func (c *Conn) Read(ctx context.Context) ([]byte, error) {
	typ, data, err := c.ws.Read(ctx)
	if err != nil {
		c.cancel(err)
		return nil, err
	}
	if typ != websocket.MessageText {
		err := errors.New("binary frames are not part of the protocol")
		c.Close(websocket.StatusUnsupportedData, "text frames only")
		return nil, err
	}
	return data, nil
}

// Close closes the connection with a WebSocket close code and stops the
// writer. Messages still queued are dropped.
func (c *Conn) Close(code websocket.StatusCode, reason string) {
	c.cancel(ErrConnClosed)
	_ = c.ws.Close(code, reason)
	c.wg.Wait()
}

// CloseAfterFlush waits up to wait for the send queue to drain, then closes.
func (c *Conn) CloseAfterFlush(code websocket.StatusCode, reason string, wait time.Duration) {
	deadline := time.Now().Add(wait)
	for len(c.sendq) > 0 && time.Now().Before(deadline) && c.ctx.Err() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	// Give the writer a moment to put the last dequeued frame on the wire.
	time.Sleep(20 * time.Millisecond)
	c.Close(code, reason)
}

func (c *Conn) writeLoop() {
	defer c.wg.Done()
	tokens := float64(sendBurst)
	last := time.Now()
	for {
		var msg []byte
		select {
		case <-c.ctx.Done():
			return
		case msg = <-c.sendq:
		}
		// Token bucket: stay below the server's per-connection rate limit.
		now := time.Now()
		tokens += now.Sub(last).Seconds() * sendRatePerSecond
		last = now
		if tokens > sendBurst {
			tokens = sendBurst
		}
		if tokens < 1 {
			wait := time.Duration((1 - tokens) / sendRatePerSecond * float64(time.Second))
			t := time.NewTimer(wait)
			select {
			case <-c.ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			tokens = 1
			last = time.Now()
		}
		tokens--
		wctx, cancel := context.WithTimeout(c.ctx, c.writeTimeout)
		err := c.ws.Write(wctx, websocket.MessageText, msg)
		cancel()
		if err != nil {
			c.cancel(fmt.Errorf("write: %w", err))
			return
		}
	}
}

func (c *Conn) pingLoop(every time.Duration) {
	defer c.wg.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(c.ctx, every)
		err := c.ws.Ping(pctx)
		cancel()
		if err != nil {
			c.cancel(fmt.Errorf("keepalive ping: %w", err))
			_ = c.ws.CloseNow()
			return
		}
	}
}

// Client maintains the control connection: dial, serve, reconnect.
type Client struct {
	// ServerURL is the https origin of the agent listener.
	ServerURL string
	// TLS returns the TLS policy for the next dial (see NewTLSConfig). It is
	// called per dial so trust and certificate changes take effect.
	TLS func() *tls.Config
	// Logger receives connection state changes.
	Logger *slog.Logger
	// OnState is called after every connect (true, nil) and disconnect (false, cause).
	OnState func(connected bool, err error)

	// Optional tunables (zero values use the defaults).
	Backoff      *Backoff
	SendQueue    int
	PingInterval time.Duration
	WriteTimeout time.Duration
	DialTimeout  time.Duration
	// Sleep waits for d or until ctx ends (tests replace it).
	Sleep func(ctx context.Context, d time.Duration) error

	mu      sync.Mutex
	skipOne bool
}

// ReconnectNow makes the next reconnect skip its backoff delay. It is used
// after an intentional local close (certificate renewal, trust rotation).
func (c *Client) ReconnectNow() {
	c.mu.Lock()
	c.skipOne = true
	c.mu.Unlock()
}

func (c *Client) takeSkip() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.skipOne
	c.skipOne = false
	return s
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Dial opens one connection.
func (c *Client) Dial(ctx context.Context) (*Conn, error) {
	if !strings.HasPrefix(c.ServerURL, "https://") {
		return nil, errors.New("server URL must be https")
	}
	dialTimeout := c.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	// A dedicated transport per dial: no pooled connections, current trust.
	httpClient := NewHTTPClient(c.TLS(), 0)
	// On success the response body is the hijacked connection owned by ws;
	// on failure it is closed below.
	ws, resp, err := websocket.Dial(dctx, "wss://"+strings.TrimPrefix(c.ServerURL, "https://")+WSPath, &websocket.DialOptions{
		HTTPClient:      httpClient,
		Subprotocols:    []string{protocol.Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		revoked := false
		if resp != nil {
			revoked = resp.StatusCode == http.StatusForbidden
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		}
		if revoked {
			return nil, ErrRevoked
		}
		return nil, err
	}
	if ws.Subprotocol() != protocol.Subprotocol {
		_ = ws.Close(websocket.StatusProtocolError, "subprotocol required")
		return nil, fmt.Errorf("server did not select subprotocol %s", protocol.Subprotocol)
	}
	queue := c.SendQueue
	if queue <= 0 {
		queue = DefaultSendQueue
	}
	ping := c.PingInterval
	if ping <= 0 {
		ping = DefaultPingInterval
	}
	wt := c.WriteTimeout
	if wt <= 0 {
		wt = DefaultWriteTimeout
	}
	return newConn(ctx, ws, queue, ping, wt), nil
}

// Run keeps a connection up until ctx ends. serve is called once per
// established connection and must return when the connection is finished;
// the connection is closed afterwards if serve left it open.
func (c *Client) Run(ctx context.Context, serve func(ctx context.Context, conn *Conn) error) error {
	log := c.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	bo := c.Backoff
	if bo == nil {
		bo = NewBackoff()
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = defaultSleep
	}
	revoked := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := c.Dial(ctx)
		if err == nil {
			revoked = false
			started := time.Now()
			log.Info("connected to server", slog.String("server", c.ServerURL))
			if c.OnState != nil {
				c.OnState(true, nil)
			}
			err = serve(conn.ctx, conn)
			if err == nil {
				err = conn.Err()
			}
			conn.Close(websocket.StatusNormalClosure, "")
			if c.OnState != nil {
				c.OnState(false, err)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if time.Since(started) >= StableAfter {
				bo.Reset()
			}
			log.Warn("disconnected from server", slog.Any("error", err))
		} else {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, ErrRevoked) {
				revoked = true
			}
			if c.OnState != nil {
				c.OnState(false, err)
			}
			log.Warn("connect failed", slog.Any("error", err), slog.Bool("revoked", revoked))
		}
		if c.takeSkip() {
			continue
		}
		limit := time.Duration(0)
		if revoked {
			limit = BackoffRevokedCap
		}
		delay := bo.NextWithCap(limit)
		if err := sleep(ctx, delay); err != nil {
			return err
		}
	}
}
