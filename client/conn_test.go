package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/dotwaffle/sshpd/protocol"
	"github.com/dotwaffle/sshpd/relay"
)

func peerRead(ctx context.Context, ws *websocket.Conn) (protocol.Packet, error) {
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return protocol.Packet{}, err
	}
	if typ != websocket.MessageBinary {
		return protocol.Packet{}, ErrProtocol
	}
	return protocol.Decode(data)
}

func peerWrite(ctx context.Context, ws *websocket.Conn, p protocol.Packet) error {
	data, err := protocol.Encode(p)
	if err != nil {
		return err
	}
	return ws.Write(ctx, websocket.MessageBinary, data)
}

func waitPeerClose(ctx context.Context, ws *websocket.Conn) {
	for {
		if _, _, err := ws.Read(ctx); err != nil {
			return
		}
	}
}

func nativeServer(t *testing.T, handler http.HandlerFunc) Config {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return Config{URL: s.URL, Destination: relay.Endpoint{Host: "home"}, AllowInsecure: true,
		Header: http.Header{"Authorization": []string{"one-use-ticket"}}, Logger: slog.New(slog.DiscardHandler),
		MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, ResumeWindow: time.Second,
		HandshakeTimeout: time.Second, WriteTimeout: time.Second}
}

func openNative(t *testing.T, cfg Config) *Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)
	c, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func scriptedPeer(t *testing.T, script func(context.Context, *websocket.Conn, *http.Request) error) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"ssh"}})
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer ws.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err = script(ctx, ws, r); err != nil {
			t.Errorf("peer script: %v", err)
		}
	}
}

func TestReplayAfterDisconnectWithoutACK(t *testing.T) {
	for _, accepted := range []int{0, 2, 6} {
		t.Run(strconv.Itoa(accepted), func(t *testing.T) {
			var admissions, resumes atomic.Int32
			complete := make(chan error, 1)
			cfg := nativeServer(t, scriptedPeer(t, func(ctx context.Context, ws *websocket.Conn, r *http.Request) error {
				if r.URL.Path == "/v4/connect" {
					admissions.Add(1)
					if r.Header.Get("Authorization") != "one-use-ticket" || r.URL.Query().Get("host") != "home" {
						return errors.New("missing initial ticket or destination")
					}
					if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte("test-sid")}); err != nil {
						return err
					}
					p, err := peerRead(ctx, ws)
					if err != nil || p.Tag != protocol.Data || string(p.Bytes) != "abcdef" {
						return fmt.Errorf("initial data %q: %w", p.Bytes, err)
					}
					// Simulate a transport loss after accepting a prefix, without an ACK.
					return nil
				}
				resumes.Add(1)
				if r.URL.Path != "/v4/reconnect" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("sid") != "test-sid" || r.URL.Query().Get("ack") != "0" {
					return errors.New("resume reused admission or lost SID")
				}
				if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.ReconnectSuccess, Position: uint64(accepted)}); err != nil {
					return err
				}
				if accepted < 6 {
					p, err := peerRead(ctx, ws)
					if err != nil || p.Tag != protocol.Data || string(p.Bytes) != "abcdef"[accepted:] {
						return fmt.Errorf("missing replay suffix %q: %w", p.Bytes, err)
					}
					if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.ACK, Position: 6}); err != nil {
						return err
					}
				}
				if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.Data, Bytes: []byte("ok")}); err != nil {
					return err
				}
				p, err := peerRead(ctx, ws)
				if err == nil && (p.Tag != protocol.ACK || p.Position != 2) {
					err = errors.New("missing output ACK")
				}
				complete <- err
				_, _, _ = ws.Read(ctx)
				return nil
			}))
			c := openNative(t, cfg)
			if n, err := c.Write([]byte("abcdef")); err != nil || n != 6 {
				t.Fatalf("write %d: %v", n, err)
			}
			output := make([]byte, 2)
			if _, err := io.ReadFull(c, output); err != nil || string(output) != "ok" {
				t.Fatalf("output %q: %v", output, err)
			}
			if err := <-complete; err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			pending := c.output.Len()
			c.mu.Unlock()
			if admissions.Load() != 1 || resumes.Load() != 1 || pending != 0 {
				t.Fatalf("admissions=%d resumes=%d pending=%d", admissions.Load(), resumes.Load(), pending)
			}
		})
	}
}

func TestResumeAcknowledgesBufferedOutputWithoutDuplicates(t *testing.T) {
	buffered, drop := make(chan struct{}), make(chan struct{})
	resumed := make(chan struct{})
	cfg := nativeServer(t, scriptedPeer(t, func(ctx context.Context, ws *websocket.Conn, r *http.Request) error {
		if r.URL.Path == "/v4/connect" {
			if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte("test-sid")}); err != nil {
				return err
			}
			if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.Data, Bytes: []byte("abcdef")}); err != nil {
				return err
			}
			p, err := peerRead(ctx, ws)
			if err != nil || p.Tag != protocol.ACK || p.Position != 6 {
				return errors.New("buffered output was not acknowledged")
			}
			close(buffered)
			select {
			case <-drop:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}
		if r.URL.Query().Get("ack") != "6" {
			return errors.New("resume did not include buffered output")
		}
		if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.ReconnectSuccess}); err != nil {
			return err
		}
		if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.Data, Bytes: []byte("gh")}); err != nil {
			return err
		}
		close(resumed)
		waitPeerClose(ctx, ws)
		return nil
	}))
	c := openNative(t, cfg)
	<-buffered
	first := make([]byte, 2)
	if _, err := io.ReadFull(c, first); err != nil || string(first) != "ab" {
		t.Fatalf("first output %q: %v", first, err)
	}
	close(drop)
	<-resumed
	rest := make([]byte, 6)
	if _, err := io.ReadFull(c, rest); err != nil || string(rest) != "cdefgh" {
		t.Fatalf("remaining output %q: %v", rest, err)
	}
}

func TestPermanentResumeLossPreservesFinalOutput(t *testing.T) {
	var admissions, resumes atomic.Int32
	script := scriptedPeer(t, func(ctx context.Context, ws *websocket.Conn, _ *http.Request) error {
		if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte("test-sid")}); err != nil {
			return err
		}
		if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.Data, Bytes: []byte("final")}); err != nil {
			return err
		}
		_, err := peerRead(ctx, ws)
		return err
	})
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v4/reconnect" {
			resumes.Add(1)
			http.Error(w, "gone", http.StatusGone)
			return
		}
		admissions.Add(1)
		script(w, r)
	})
	c := openNative(t, cfg)
	<-c.done
	output := make([]byte, 5)
	if _, err := io.ReadFull(c, output); err != nil || string(output) != "final" {
		t.Fatalf("final output %q: %v", output, err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, ErrGone) {
		t.Fatalf("terminal error: %v", err)
	}
	if admissions.Load() != 1 || resumes.Load() != 1 {
		t.Fatal("permanent loss started another admission or retry")
	}
}

func TestCancellationUnblocksReadAndBackpressuredWrite(t *testing.T) {
	data := make(chan struct{})
	cfg := nativeServer(t, scriptedPeer(t, func(ctx context.Context, ws *websocket.Conn, _ *http.Request) error {
		if err := peerWrite(ctx, ws, protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte("test-sid")}); err != nil {
			return err
		}
		if _, err := peerRead(ctx, ws); err != nil {
			return err
		}
		close(data)
		_, _, _ = ws.Read(ctx)
		return nil
	}))
	cfg.ReplayBytes = 3
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() { _, readErr := c.Read(make([]byte, 1)); readDone <- readErr }()
	go func() {
		n, writeErr := c.Write([]byte("abcdef"))
		if n != 3 {
			writeErr = fmt.Errorf("backpressure accepted %d bytes", n)
		}
		writeDone <- writeErr
	}()
	<-data
	select {
	case err = <-writeDone:
		t.Fatalf("full replay buffer did not block: %v", err)
	default:
	}
	cancel()
	for _, done := range []<-chan error{readDone, writeDone} {
		select {
		case err = <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation did not release stream")
		}
	}
}

func TestACKCannotDiscardQueuedUnsentBytes(t *testing.T) {
	for _, position := range []uint64{4, 6} {
		t.Run(strconv.FormatUint(position, 10), func(t *testing.T) {
			c := &Conn{sentTop: 3}
			c.output.Append([]byte("abcdef"), 6)
			if err := c.acknowledgeLocked(position); !errors.Is(err, ErrProtocol) || c.output.Len() != 6 {
				t.Fatalf("accepted unsent ACK %d: %v", position, err)
			}
		})
	}
}
