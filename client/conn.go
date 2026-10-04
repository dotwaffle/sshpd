// Package client exposes a resumable corp-relay-v4 byte stream for native SSH.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/dotwaffle/sshpd/internal/replay"
	"github.com/dotwaffle/sshpd/protocol"
	"github.com/dotwaffle/sshpd/relay"
)

// Native transport errors never include URLs, which can contain resume SIDs.
var (
	ErrGone      = errors.New("relay session gone")
	ErrProtocol  = errors.New("invalid relay protocol")
	ErrTransport = errors.New("relay transport unavailable")
	ErrDenied    = errors.New("relay admission denied")
)

// Config controls a native protocol connection. Header applies only to the
// initial admission, so consumed tickets are never reused during resume.
// AllowInsecure permits plain WebSockets for explicit local test deployments.
type Config struct {
	URL                                                                  string
	Destination                                                          relay.Endpoint
	Header                                                               http.Header
	HTTPClient                                                           *http.Client
	Logger                                                               *slog.Logger
	AllowInsecure                                                        bool
	ReplayBytes                                                          int
	ResumeWindow, MinBackoff, MaxBackoff, HandshakeTimeout, WriteTimeout time.Duration
}

// Conn is a byte stream with bounded replay in both directions. One reader and
// one writer may use it concurrently. Context cancellation ends the stream.
// Closing the local stream drops its WebSocket. Backend retention remains a
// server policy unless SSH itself closes its backend connection.
type Conn struct {
	mu            sync.Mutex
	cfg           Config
	base          url.URL
	sid           string
	input, output replay.Buffer
	received      uint64
	sentTop       uint64
	err           error
	changed       chan struct{}
	cancel        context.CancelFunc
	done          chan struct{}
}

// Open performs one fresh admission. Transport retries after this point use
// only the returned SID. It never silently creates another backend connection.
// The supplied ctx controls the lifetime of the returned stream.
func Open(ctx context.Context, cfg Config) (*Conn, error) {
	base, err := prepare(&cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &Conn{cfg: cfg, base: *base, changed: make(chan struct{}), cancel: cancel, done: make(chan struct{})}
	ws, hello, err := c.dial(ctx, false)
	if err != nil {
		cancel()
		return nil, err
	}
	c.sid = string(hello.Bytes)
	c.cfg.Header = nil
	go c.loop(ctx, ws)
	return c, nil
}

func prepare(cfg *Config) (*url.URL, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid relay URL")
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	if u.Scheme != "wss" && (!cfg.AllowInsecure || u.Scheme != "ws") {
		return nil, errors.New("relay requires HTTPS or WSS")
	}
	cfg.Destination, err = cfg.Destination.Normalize()
	if err != nil {
		return nil, err
	}
	cfg.Header = cfg.Header.Clone()
	// A redirect must not move a ticket or SID to another endpoint or cause
	// a reconnect request to create a fresh backend through a different route.
	httpClient := http.DefaultClient
	if cfg.HTTPClient != nil {
		httpClient = cfg.HTTPClient
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTPClient = &copyClient
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if cfg.ReplayBytes == 0 {
		cfg.ReplayBytes = 1 << 20
	}
	if cfg.ResumeWindow == 0 {
		cfg.ResumeWindow = 15 * time.Minute
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 10 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if cfg.ReplayBytes < 1 || cfg.ResumeWindow < 0 || cfg.MinBackoff < 0 || cfg.MaxBackoff < cfg.MinBackoff || cfg.HandshakeTimeout < 0 || cfg.WriteTimeout < 0 {
		return nil, errors.New("invalid native relay limits")
	}
	return u, nil
}

func (c *Conn) dial(ctx context.Context, resume bool) (*websocket.Conn, protocol.Packet, error) {
	u := c.base
	q := make(url.Values)
	path := "/v4/connect"
	headers := c.cfg.Header
	if resume {
		path = "/v4/reconnect"
		q.Set("sid", c.sid)
		c.mu.Lock()
		q.Set("ack", strconv.FormatUint(c.received, 10))
		c.mu.Unlock()
		headers = nil
	} else {
		q.Set("host", c.cfg.Destination.Host)
		q.Set("port", strconv.Itoa(int(c.cfg.Destination.Port)))
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = q.Encode()
	handshakeCtx, cancel := context.WithTimeout(ctx, c.cfg.HandshakeTimeout)
	defer cancel()
	ws, response, err := websocket.Dial(handshakeCtx, u.String(), &websocket.DialOptions{HTTPClient: c.cfg.HTTPClient, HTTPHeader: headers, Subprotocols: []string{"ssh"}})
	if err != nil {
		if response != nil {
			if response.Body != nil {
				_ = response.Body.Close()
			}
			switch response.StatusCode {
			case http.StatusGone:
				return nil, protocol.Packet{}, ErrGone
			case http.StatusBadRequest:
				return nil, protocol.Packet{}, ErrProtocol
			case http.StatusUnauthorized, http.StatusForbidden:
				return nil, protocol.Packet{}, ErrDenied
			}
		}
		return nil, protocol.Packet{}, ErrTransport
	}
	ws.SetReadLimit(protocol.MaxArray + 6)
	typ, b, err := ws.Read(handshakeCtx)
	if err != nil {
		_ = ws.CloseNow()
		return nil, protocol.Packet{}, transportError(err)
	}
	hello, err := protocol.Decode(b)
	want := protocol.ConnectSuccess
	if resume {
		want = protocol.ReconnectSuccess
	}
	if err != nil || typ != websocket.MessageBinary || hello.Tag != want || ws.Subprotocol() != "ssh" {
		_ = ws.CloseNow()
		return nil, protocol.Packet{}, ErrProtocol
	}
	return ws, hello, nil
}

// Read returns backend bytes. Buffered bytes are delivered before a terminal
// transport error, including the final output from a closed backend.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if c.input.Len() > 0 {
			data, err := c.input.ReadAt(c.input.Base(), len(p))
			if err != nil {
				c.mu.Unlock()
				return 0, ErrProtocol
			}
			n := copy(p, data)
			_ = c.input.Acknowledge(c.input.Base() + uint64(len(data)))
			c.signalLocked()
			c.mu.Unlock()
			return n, nil
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		wake := c.changed
		c.mu.Unlock()
		<-wake
	}
}

// Write queues bytes in the bounded client replay buffer. A full buffer blocks
// until the relay acknowledges bytes or the stream ends.
func (c *Conn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		c.mu.Lock()
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return written, err
		}
		n := min(len(p), c.cfg.ReplayBytes-c.output.Len())
		if n > 0 {
			capacity, ok := c.output.RequiredCapacity(n, c.cfg.ReplayBytes)
			if !ok {
				c.mu.Unlock()
				return written, ErrProtocol
			}
			c.output.Append(p[:n], capacity)
			c.signalLocked()
			c.mu.Unlock()
			written += n
			p = p[n:]
			continue
		}
		wake := c.changed
		c.mu.Unlock()
		<-wake
	}
	return written, nil
}

// Flush waits until the relay acknowledges all queued output. It does not
// promise delivery by the backend or send an SSH-level disconnect.
func (c *Conn) Flush(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.output.Len() == 0 {
			c.mu.Unlock()
			return nil
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return err
		}
		wake := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

// Close cancels retries and ends the local stream.
func (c *Conn) Close() error { c.finish(io.ErrClosedPipe); c.cancel(); <-c.done; return nil }

func (c *Conn) signalLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *Conn) finish(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
		c.signalLocked()
	}
	c.mu.Unlock()
}

func (c *Conn) loop(ctx context.Context, ws *websocket.Conn) {
	defer close(c.done)
	defer c.cancel()
	for {
		err := c.exchange(ctx, ws)
		_ = ws.CloseNow()
		if ctx.Err() != nil {
			c.finish(ctx.Err())
			return
		}
		if permanent(err) {
			c.finish(err)
			return
		}
		var resumeErr error
		ws, resumeErr = c.retry(ctx)
		if resumeErr != nil {
			c.finish(resumeErr)
			return
		}
	}
}

func permanent(err error) bool {
	return errors.Is(err, ErrGone) || errors.Is(err, ErrDenied) || errors.Is(err, ErrProtocol)
}

func transportError(err error) error {
	switch websocket.CloseStatus(err) {
	case websocket.StatusPolicyViolation, websocket.StatusProtocolError, websocket.StatusMessageTooBig:
		return ErrProtocol
	default:
		return ErrTransport
	}
}

func (c *Conn) retry(ctx context.Context) (*websocket.Conn, error) {
	deadline := time.Now().Add(c.cfg.ResumeWindow)
	delay := c.cfg.MinBackoff
	for time.Now().Before(deadline) {
		wait := delay/2 + time.Duration(rand.Int64N(int64(max(delay/2, time.Nanosecond))))
		timer := time.NewTimer(min(wait, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		attemptCtx, cancel := context.WithDeadline(ctx, deadline)
		ws, hello, err := c.dial(attemptCtx, true)
		cancel()
		if err == nil {
			c.mu.Lock()
			ackErr := c.acknowledgeLocked(hello.Position)
			c.signalLocked()
			c.mu.Unlock()
			if ackErr != nil {
				_ = ws.CloseNow()
				return nil, ErrProtocol
			}
			c.cfg.Logger.DebugContext(ctx, "relay session resumed")
			return ws, nil
		}
		if permanent(err) {
			return nil, err
		}
		c.cfg.Logger.DebugContext(ctx, "relay resume retry", slog.Duration("backoff", delay))
		if delay < c.cfg.MaxBackoff {
			delay += min(delay, c.cfg.MaxBackoff-delay)
		}
	}
	return nil, ErrTransport
}

func (c *Conn) exchange(ctx context.Context, ws *websocket.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); c.send(ctx, ws); _ = ws.CloseNow() }()
	err := c.receive(ctx, ws)
	cancel()
	_ = ws.CloseNow()
	<-done
	return err
}

func (c *Conn) send(ctx context.Context, ws *websocket.Conn) {
	// Each attachment starts at the server's accepted offset, not the previous
	// attachment's send cursor. This replays bytes after a lost write or ACK.
	c.mu.Lock()
	cursor := c.output.Base()
	c.mu.Unlock()
	for {
		c.mu.Lock()
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		data, err := c.output.ReadAt(cursor, protocol.MaxArray)
		wake := c.changed
		if err == nil {
			c.sentTop = max(c.sentTop, cursor+uint64(len(data)))
		}
		c.mu.Unlock()
		if err != nil {
			c.finish(ErrProtocol)
			return
		}
		if len(data) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				continue
			}
		}
		if err := c.write(ctx, ws, protocol.Packet{Tag: protocol.Data, Bytes: data}); err != nil {
			return
		}
		cursor += uint64(len(data))
	}
}

func (c *Conn) write(ctx context.Context, ws *websocket.Conn, p protocol.Packet) error {
	b, err := protocol.Encode(p)
	if err != nil {
		return ErrProtocol
	}
	writeCtx, cancel := context.WithTimeout(ctx, c.cfg.WriteTimeout)
	defer cancel()
	if err := ws.Write(writeCtx, websocket.MessageBinary, b); err != nil {
		return transportError(err)
	}
	return nil
}

func (c *Conn) receive(ctx context.Context, ws *websocket.Conn) error {
	for {
		typ, b, err := ws.Read(ctx)
		if err != nil {
			return transportError(err)
		}
		p, err := protocol.Decode(b)
		if err != nil || typ != websocket.MessageBinary {
			return ErrProtocol
		}
		switch p.Tag {
		case protocol.ACK:
			c.mu.Lock()
			err = c.acknowledgeLocked(p.Position)
			c.signalLocked()
			c.mu.Unlock()
			if err != nil {
				return ErrProtocol
			}
		case protocol.Data:
			if err := c.acceptData(ctx, p.Bytes); err != nil {
				return err
			}
			c.mu.Lock()
			received := c.received
			c.mu.Unlock()
			if err := c.write(ctx, ws, protocol.Packet{Tag: protocol.ACK, Position: received}); err != nil {
				return err
			}
		case protocol.ConnectSuccess, protocol.ReconnectSuccess:
			return ErrProtocol
		}
	}
}

func (c *Conn) acknowledgeLocked(position uint64) error {
	if position > c.sentTop {
		return ErrProtocol
	}
	return c.output.Acknowledge(position)
}

func (c *Conn) acceptData(ctx context.Context, data []byte) error {
	for {
		c.mu.Lock()
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return err
		}
		if uint64(len(data)) > math.MaxUint64-c.received {
			c.mu.Unlock()
			return ErrProtocol
		}
		capacity, ok := c.input.RequiredCapacity(len(data), c.cfg.ReplayBytes)
		if ok {
			c.input.Append(data, capacity)
			c.received += uint64(len(data))
			c.signalLocked()
			c.mu.Unlock()
			return nil
		}
		if len(data) > c.cfg.ReplayBytes {
			c.mu.Unlock()
			return fmt.Errorf("backend frame exceeds client capacity: %w", ErrProtocol)
		}
		wake := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}
