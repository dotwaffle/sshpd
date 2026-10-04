package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/dotwaffle/sshpd/protocol"
)

type authorizeFunc func(context.Context, *http.Request, Endpoint) (Grant, error)

func (f authorizeFunc) Admit(ctx context.Context, r *http.Request, e Endpoint) (Grant, error) {
	return f(ctx, r, e)
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type auditFunc func(context.Context, AuditEvent) error

func (f auditFunc) Record(ctx context.Context, e AuditEvent) error { return f(ctx, e) }

type harness struct {
	s      *Server
	http   *httptest.Server
	r      *Registry
	peers  chan net.Conn
	events chan AuditEvent
	dials  atomic.Int32
	now    atomic.Int64
}

func newHarness(t *testing.T, change func(*Config)) *harness {
	t.Helper()
	h := &harness{peers: make(chan net.Conn, 32), events: make(chan AuditEvent, 128)}
	h.now.Store(time.Now().UnixNano())
	r, err := NewRegistry([]Destination{{ID: "home", Aliases: []Endpoint{{Host: "home"}, {Host: "home.example"}}, Backend: Endpoint{Host: "127.0.0.1", Port: 2222}}})
	if err != nil {
		t.Fatal(err)
	}
	h.r = r
	cfg := Config{Resolver: r, Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return time.Unix(0, h.now.Load()) },
		Authorizer: authorizeFunc(func(_ context.Context, r *http.Request, _ Endpoint) (Grant, error) {
			g := Grant{UserID: "user", LoginID: "login", ClientKind: "terminal", ClientID: "profile"}
			if id := r.Header.Get("X-Test-User"); id != "" {
				g.UserID = id
			}
			if id := r.Header.Get("X-Test-Login"); id != "" {
				g.LoginID = id
			}
			if id := r.Header.Get("X-Test-Client"); id != "" {
				g.ClientID = id
			}
			return g, nil
		}),
		Dialer: dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			server, peer := net.Pipe()
			h.dials.Add(1)
			select {
			case h.peers <- peer:
				return server, nil
			case <-ctx.Done():
				server.Close()
				peer.Close()
				return nil, ctx.Err()
			}
		}),
		Audit: auditFunc(func(ctx context.Context, e AuditEvent) error {
			select {
			case h.events <- e:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})}
	if change != nil {
		change(&cfg)
	}
	h.s, err = New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.http = httptest.NewServer(h.s)
	t.Cleanup(func() {
		h.s.Close()
		h.http.Close()
		for {
			select {
			case p := <-h.peers:
				p.Close()
			default:
				return
			}
		}
	})
	return h
}

func (h *harness) connect(t *testing.T, headers http.Header) (*websocket.Conn, string, net.Conn) {
	t.Helper()
	ws, response, err := websocket.Dial(t.Context(), strings.Replace(h.http.URL, "http:", "ws:", 1)+"/v4/connect?host=home", &websocket.DialOptions{Subprotocols: []string{"ssh"}, HTTPHeader: headers})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	hello := readCommand(t, ws)
	if hello.Tag != protocol.ConnectSuccess {
		t.Fatal("missing connect success")
	}
	peer := <-h.peers
	t.Cleanup(func() { peer.Close() })
	return ws, string(hello.Bytes), peer
}

func (h *harness) resume(t *testing.T, sid string, ack uint64) (*websocket.Conn, protocol.Packet) {
	t.Helper()
	u := strings.Replace(h.http.URL, "http:", "ws:", 1) + "/v4/reconnect?sid=" + url.QueryEscape(sid) + "&ack=" + strconv.FormatUint(ack, 10)
	ws, response, err := websocket.Dial(t.Context(), u, &websocket.DialOptions{Subprotocols: []string{"ssh"}})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws, readCommand(t, ws)
}

func (h *harness) waitEvent(t *testing.T, kind string) AuditEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for {
		select {
		case e := <-h.events:
			if e.Kind == kind {
				return e
			}
		case <-ctx.Done():
			t.Fatalf("missing audit event %s", kind)
		}
	}
}

func readCommand(t *testing.T, ws *websocket.Conn) protocol.Packet {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	typ, b, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := protocol.Decode(b)
	if err != nil || typ != websocket.MessageBinary {
		t.Fatalf("invalid command: %v", err)
	}
	return p
}
func sendCommand(t *testing.T, ws *websocket.Conn, p protocol.Packet) {
	t.Helper()
	b, err := protocol.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := ws.Write(ctx, websocket.MessageBinary, b); err != nil {
		t.Fatal(err)
	}
}
func await(t *testing.T, predicate func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()
	for !predicate() {
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("condition timed out")
		}
	}
}

func TestReconnectKeepsBackendAndReplaysBothDirections(t *testing.T) {
	h := newHarness(t, nil)
	ws, sid, peer := h.connect(t, nil)
	sendCommand(t, ws, protocol.Packet{Tag: protocol.Data, Bytes: []byte("abc")})
	input := make([]byte, 3)
	if _, err := io.ReadFull(peer, input); err != nil || string(input) != "abc" {
		t.Fatalf("backend input %q: %v", input, err)
	}
	// Drop transport without reading its ACK.
	ws.CloseNow()
	h.waitEvent(t, "session.detach")
	if _, err := peer.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	resumed, hello := h.resume(t, sid, 0)
	if hello.Tag != protocol.ReconnectSuccess || hello.Position != 3 {
		t.Fatalf("accepted offset %+v", hello)
	}
	output := readCommand(t, resumed)
	if output.Tag != protocol.Data || string(output.Bytes) != "abcdef" {
		t.Fatalf("backend replay %+v", output)
	}
	// Only acknowledge a prefix, then resume and receive the missing suffix.
	resumed.CloseNow()
	h.waitEvent(t, "session.detach")
	next, hello := h.resume(t, sid, 3)
	if hello.Position != 3 {
		t.Fatal("client offset changed")
	}
	output = readCommand(t, next)
	if string(output.Bytes) != "def" {
		t.Fatalf("missing suffix %q", output.Bytes)
	}
	if h.dials.Load() != 1 {
		t.Fatal("resume redialed backend")
	}
	sendCommand(t, next, protocol.Packet{Tag: protocol.ACK, Position: 6})
	await(t, func() bool { return h.s.Stats().ReplayCapacity == 0 })
}

func TestReplacementOnlyClosesDetachedMatchingIdentity(t *testing.T) {
	for _, test := range []struct {
		name, client string
		replace      bool
	}{{"same profile", "", true}, {"different profile", "other", false}} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t, nil)
			ws, sid, _ := h.connect(t, nil)
			ws.CloseNow()
			h.waitEvent(t, "session.detach")
			h.now.Add(int64(61 * time.Second))
			h.connect(t, http.Header{"X-Test-Client": []string{test.client}})
			h.s.mu.Lock()
			exists := h.s.sessions[sid] != nil
			h.s.mu.Unlock()
			if exists == test.replace {
				t.Fatalf("old session exists=%v", exists)
			}
		})
	}
	h := newHarness(t, nil)
	_, sid, _ := h.connect(t, nil)
	h.now.Add(int64(2 * time.Minute))
	h.connect(t, nil)
	h.s.mu.Lock()
	exists := h.s.sessions[sid] != nil
	h.s.mu.Unlock()
	if !exists {
		t.Fatal("attached tab replaced")
	}
}

func TestMemoryPressureProtectsAttachedAndCreditsReleasedBuffers(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MemoryLimit = 1000; c.Limits.ReplayBudget = 1024 })
	first, firstSID, p1 := h.connect(t, nil)
	first.CloseNow()
	h.waitEvent(t, "session.detach")
	p1.Write([]byte("a"))
	second, secondSID, p2 := h.connect(t, http.Header{"X-Test-Client": []string{"second"}})
	second.CloseNow()
	h.waitEvent(t, "session.detach")
	p2.Write(make([]byte, 200))
	_, attachedSID, p3 := h.connect(t, http.Header{"X-Test-Client": []string{"attached"}})
	p3.Write(make([]byte, 257))
	await(t, func() bool { return h.s.Stats().ReplayCapacity == 896 })
	h.now.Add(int64(61 * time.Second))
	h.s.sweep(h.s.cfg.Now(), 850)
	h.s.mu.Lock()
	firstAlive, secondAlive, attachedAlive := h.s.sessions[firstSID] != nil, h.s.sessions[secondSID] != nil, h.s.sessions[attachedSID] != nil
	h.s.mu.Unlock()
	if !firstAlive || secondAlive || !attachedAlive {
		t.Fatalf("wrong victims: %v %v %v", firstAlive, secondAlive, attachedAlive)
	}
	// A stale sample after the cooldown must not evict the smaller session.
	h.now.Add(int64(10 * time.Second))
	h.s.sweep(h.s.cfg.Now(), 850)
	if stats := h.s.Stats(); stats.Detached != 1 || stats.Attached != 1 {
		t.Fatalf("overeviction: %+v", stats)
	}
}

func TestRevocationClosesOnlyMatchingLogin(t *testing.T) {
	h := newHarness(t, nil)
	first, sid, _ := h.connect(t, nil)
	first.CloseNow()
	h.waitEvent(t, "session.detach")
	_, otherSID, _ := h.connect(t, http.Header{"X-Test-Login": []string{"other"}, "X-Test-Client": []string{"other"}})
	h.s.RevokeLogin("login")
	h.s.mu.Lock()
	gone, otherAlive := h.s.sessions[sid] == nil, h.s.sessions[otherSID] != nil
	h.s.mu.Unlock()
	if !gone || !otherAlive {
		t.Fatal("incorrect logout scope")
	}
}

func TestAuditFailurePolicy(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(strconv.FormatBool(strict), func(t *testing.T) {
			h := newHarness(t, func(c *Config) {
				c.StrictAudit = strict
				c.Audit = auditFunc(func(context.Context, AuditEvent) error { return errors.New("sink unavailable") })
			})
			ws, response, err := websocket.Dial(t.Context(), strings.Replace(h.http.URL, "http:", "ws:", 1)+"/v4/connect?host=home", &websocket.DialOptions{Subprotocols: []string{"ssh"}})
			if strict {
				if err == nil || response == nil || response.StatusCode != http.StatusServiceUnavailable {
					t.Fatal("strict admission succeeded")
				}
				if response.Body != nil {
					response.Body.Close()
				}
				if h.s.Stats().Attached+h.s.Stats().Detached != 0 {
					t.Fatal("failed admission retained backend")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ws.CloseNow() })
				readCommand(t, ws)
			}
			await(t, func() bool { return h.s.Stats().AuditLost > 0 })
		})
	}
}

func TestRevocationDuringAuthorizationRejectsLateGrant(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := newHarness(t, func(c *Config) {
		c.Authorizer = authorizeFunc(func(ctx context.Context, _ *http.Request, _ Endpoint) (Grant, error) {
			close(entered)
			select {
			case <-release:
				return Grant{UserID: "user", LoginID: "login", ClientKind: "terminal", ClientID: "profile"}, nil
			case <-ctx.Done():
				return Grant{}, ctx.Err()
			}
		})
	})
	done := make(chan error, 1)
	go func() {
		ws, response, err := websocket.Dial(t.Context(), strings.Replace(h.http.URL, "http:", "ws:", 1)+"/v4/connect?host=home", &websocket.DialOptions{Subprotocols: []string{"ssh"}})
		if ws != nil {
			ws.CloseNow()
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		done <- err
	}()
	<-entered
	h.s.RevokeUser("user")
	close(release)
	if err := <-done; err == nil || h.dials.Load() != 0 {
		t.Fatal("late grant survived revocation")
	}
}
