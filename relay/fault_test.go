package relay

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/protocol"
)

type resolveFunc func(context.Context, Endpoint) (Target, error)

func (f resolveFunc) Resolve(ctx context.Context, e Endpoint) (Target, error) { return f(ctx, e) }

func TestAuthorizationRevocationScope(t *testing.T) {
	for _, test := range []struct {
		name, id     string
		user, denied bool
	}{
		{"matching user", "user", true, true},
		{"matching login", "login", false, true},
		{"other user", "other", true, false},
		{"other login", "other", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			h := newHarness(t, func(c *Config) {
				c.Authorizer = authorizeFunc(func(ctx context.Context, _ *http.Request, _ Endpoint) (Grant, error) {
					close(entered)
					select {
					case <-release:
						return Grant{UserID: "user", LoginID: "login", ClientKind: "native", ClientID: "installation"}, nil
					case <-ctx.Done():
						return Grant{}, ctx.Err()
					}
				})
			})
			go func() {
				h.s.connect(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
				close(done)
			}()
			<-entered
			if test.user {
				h.s.RevokeUser(test.id)
			} else {
				h.s.RevokeLogin(test.id)
			}
			close(release)
			<-done
			if (h.dials.Load() == 0) != test.denied {
				t.Fatalf("denied=%v dials=%d", test.denied, h.dials.Load())
			}
		})
	}
}

func TestRevocationCancelsPendingDialAndClosesLateBackend(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	backend, peer := net.Pipe()
	t.Cleanup(func() { backend.Close(); peer.Close() })
	h := newHarness(t, func(c *Config) {
		c.Dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) {
			close(entered)
			<-release
			// A misbehaving dialer returns success after its context is canceled.
			return backend, nil
		})
	})
	go func() {
		h.s.connect(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
		close(done)
	}()
	<-entered
	h.s.RevokeLogin("login")
	close(release)
	<-done
	if stats := h.s.Stats(); stats.Attached != 0 || stats.Detached != 0 || stats.Dialing != 0 {
		t.Fatalf("late backend survived: %+v", stats)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late backend not closed: %v", err)
	}
}

func TestReloadRejectsStaleResolution(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		t.Run(strconv.FormatBool(immediate), func(t *testing.T) {
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			h := newHarness(t, func(c *Config) {
				resolver := c.Resolver
				c.Resolver = resolveFunc(func(ctx context.Context, e Endpoint) (Target, error) {
					target, err := resolver.Resolve(ctx, e)
					close(entered)
					select {
					case <-release:
						return target, err
					case <-ctx.Done():
						return Target{}, ctx.Err()
					}
				})
			})
			go func() {
				h.s.connect(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
				close(done)
			}()
			<-entered
			if err := h.r.Replace(nil); err != nil {
				t.Fatal(err)
			}
			if err := h.s.ReconcileDestinations(t.Context(), immediate); err != nil {
				t.Fatal(err)
			}
			close(release)
			<-done
			if h.dials.Load() != 0 {
				t.Fatal("stale resolution opened backend")
			}
		})
	}
}

func TestReloadDrainsOrClosesExistingSessions(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		t.Run(strconv.FormatBool(immediate), func(t *testing.T) {
			h := newHarness(t, nil)
			ws, sid, _ := h.connect(t, nil)
			ws.CloseNow()
			h.waitEvent(t, "session.detach")
			if err := h.r.Replace(nil); err != nil {
				t.Fatal(err)
			}
			if err := h.s.ReconcileDestinations(t.Context(), immediate); err != nil {
				t.Fatal(err)
			}
			if immediate {
				event := h.waitEvent(t, "session.close")
				if event.Reason != "destination_removed" || h.s.Stats().Detached != 0 {
					t.Fatal("removed session not closed")
				}
			} else {
				_, hello := h.resume(t, sid, 0)
				if hello.Tag != protocol.ReconnectSuccess || h.dials.Load() != 1 {
					t.Fatal("draining session lost its original backend")
				}
			}
		})
	}
}

func TestNativeTicketDestinationBinding(t *testing.T) {
	for _, destination := range []string{"", "home", "other"} {
		t.Run("binding="+destination, func(t *testing.T) {
			h := newHarness(t, func(c *Config) {
				c.Authorizer = authorizeFunc(func(context.Context, *http.Request, Endpoint) (Grant, error) {
					return Grant{UserID: "user", LoginID: "login", ClientKind: "native", ClientID: "installation", DestinationID: destination}, nil
				})
			})
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home.example", http.NoBody)
			h.s.connect(httptest.NewRecorder(), r)
			if (h.dials.Load() == 0) != (destination == "other") {
				t.Fatalf("ticket binding %q: dials=%d", destination, h.dials.Load())
			}
		})
	}
}

func TestSmallReplayBufferAppliesBackpressure(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.ReplayBytes = 3; c.Limits.ReplayBudget = 3 })
	ws, _, peer := h.connect(t, nil)
	if _, err := peer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if p := readCommand(t, ws); string(p.Bytes) != "abc" {
		t.Fatalf("first data: %+v", p)
	}
	if _, err := peer.Write([]byte("def")); err != nil {
		t.Fatal(err)
	}
	peer.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := peer.Write([]byte("ghi")); err == nil {
		t.Fatal("backend reader exceeded replay cap")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	peer.SetWriteDeadline(time.Time{})
	if h.s.Stats().ReplayCapacity != 3 {
		t.Fatal("replay allocation exceeded cap")
	}
	sendCommand(t, ws, protocol.Packet{Tag: protocol.ACK, Position: 3})
	if p := readCommand(t, ws); string(p.Bytes) != "def" {
		t.Fatalf("second data: %+v", p)
	}
	sendCommand(t, ws, protocol.Packet{Tag: protocol.ACK, Position: 6})
	if _, err := peer.Write([]byte("ghi")); err != nil {
		t.Fatal(err)
	}
	if p := readCommand(t, ws); string(p.Bytes) != "ghi" {
		t.Fatalf("third data: %+v", p)
	}
}

func TestFailedDialPreservesReplacementVictim(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Sessions = 1; c.Limits.SessionsPerUser = 1 })
	ws, sid, _ := h.connect(t, nil)
	ws.CloseNow()
	h.waitEvent(t, "session.detach")
	h.now.Add(int64(61 * time.Second))
	// No request or maintenance worker reads the dialer configuration here.
	h.s.cfg.Dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("dial failed") })
	recorder := httptest.NewRecorder()
	h.s.connect(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
	if recorder.Code != http.StatusBadGateway || h.s.Stats().Detached != 1 || h.s.Stats().Dialing != 0 {
		t.Fatal("failed dial evicted old session or leaked reservation")
	}
	_, hello := h.resume(t, sid, 0)
	if hello.Tag != protocol.ReconnectSuccess {
		t.Fatal("old session cannot resume")
	}
}

func TestInvalidACKTerminatesSession(t *testing.T) {
	h := newHarness(t, nil)
	ws, _, _ := h.connect(t, nil)
	sendCommand(t, ws, protocol.Packet{Tag: protocol.ACK, Position: 1})
	event := h.waitEvent(t, "session.close")
	if event.Reason != "protocol_error" || h.s.Stats().Attached != 0 {
		t.Fatal("unsent data acknowledged")
	}
}

func TestBackendEOFPreservesFinalBytesUntilACK(t *testing.T) {
	h := newHarness(t, nil)
	ws, _, peer := h.connect(t, nil)
	if _, err := peer.Write([]byte("final")); err != nil {
		t.Fatal(err)
	}
	peer.Close()
	if p := readCommand(t, ws); string(p.Bytes) != "final" {
		t.Fatalf("final data: %+v", p)
	}
	if h.s.Stats().Attached != 1 {
		t.Fatal("EOF discarded unacknowledged output")
	}
	sendCommand(t, ws, protocol.Packet{Tag: protocol.ACK, Position: 5})
	if event := h.waitEvent(t, "session.close"); event.Reason != "backend_eof" {
		t.Fatalf("EOF close: %+v", event)
	}
}

func TestRetentionExpiryInvalidatesDetachedSID(t *testing.T) {
	h := newHarness(t, nil)
	ws, _, _ := h.connect(t, nil)
	ws.CloseNow()
	h.waitEvent(t, "session.detach")
	h.now.Add(int64(15 * time.Minute))
	h.s.sweep(h.s.cfg.Now(), 0)
	if event := h.waitEvent(t, "session.close"); event.Reason != "retention_expired" || h.s.Stats().Detached != 0 {
		t.Fatal("expired detached session retained")
	}
}

func TestPressureRejectsNaNThreshold(t *testing.T) {
	for _, high := range []bool{false, true} {
		t.Run(strconv.FormatBool(high), func(t *testing.T) {
			c := Config{Authorizer: authorizeFunc(nil), Resolver: resolveFunc(nil)}
			if high {
				c.Limits.PressureHigh = math.NaN()
			} else {
				c.Limits.PressureLow = math.NaN()
			}
			if err := defaults(&c); err == nil {
				t.Fatal("accepted NaN pressure threshold")
			}
		})
	}
}

func TestExpiredAdmissionStillAllowsSIDResume(t *testing.T) {
	var expired atomic.Bool
	h := newHarness(t, func(c *Config) {
		authorizer := c.Authorizer
		c.Authorizer = authorizeFunc(func(ctx context.Context, r *http.Request, e Endpoint) (Grant, error) {
			if expired.Load() {
				return Grant{}, ErrDenied
			}
			return authorizer.Admit(ctx, r, e)
		})
	})
	ws, sid, _ := h.connect(t, nil)
	ws.CloseNow()
	h.waitEvent(t, "session.detach")
	expired.Store(true)
	recorder := httptest.NewRecorder()
	h.s.connect(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatal("expired login opened a new session")
	}
	_, hello := h.resume(t, sid, 0)
	if hello.Tag != protocol.ReconnectSuccess || h.dials.Load() != 1 {
		t.Fatal("expiry prevented SID resume")
	}
	h.s.RevokeLogin("login")
	if h.s.Stats().Attached != 0 {
		t.Fatal("revocation failed to close resumed session")
	}
}

func TestReloadCancelsPendingDial(t *testing.T) {
	entered, done := make(chan struct{}), make(chan struct{})
	h := newHarness(t, func(c *Config) {
		c.Dialer = dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	})
	go func() {
		h.s.connect(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
		close(done)
	}()
	<-entered
	if err := h.r.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if err := h.s.ReconcileDestinations(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reload left pending dial running")
	}
	if stats := h.s.Stats(); stats.Dialing != 0 || stats.Detached != 0 {
		t.Fatal("reload leaked pending admission")
	}
}

func TestAttachedResumeFencesOldTransport(t *testing.T) {
	h := newHarness(t, nil)
	old, sid, peer := h.connect(t, nil)
	next, hello := h.resume(t, sid, 0)
	if hello.Tag != protocol.ReconnectSuccess {
		t.Fatal("missing resume")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, _, err := old.Read(ctx); err == nil {
		t.Fatal("old transport was not fenced")
	}
	if _, err := peer.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if p := readCommand(t, next); string(p.Bytes) != "next" || h.s.Stats().Attached != 1 {
		t.Fatal("old detach disrupted new attachment")
	}
}

func TestSessionQuotaAndResumeSlot(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Sessions = 2; c.Limits.SessionsPerUser = 1 })
	ws, sid, _ := h.connect(t, nil)
	recorder := httptest.NewRecorder()
	h.s.connect(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
	if recorder.Code != http.StatusTooManyRequests || h.dials.Load() != 1 {
		t.Fatal("per-user limit allowed backend dial")
	}
	h.connect(t, http.Header{"X-Test-User": []string{"second"}, "X-Test-Login": []string{"second"}})
	recorder = httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody)
	r.Header.Set("X-Test-User", "third")
	h.s.connect(recorder, r)
	if recorder.Code != http.StatusTooManyRequests || h.dials.Load() != 2 {
		t.Fatal("total session limit allowed backend dial")
	}
	ws.CloseNow()
	h.waitEvent(t, "session.detach")
	_, hello := h.resume(t, sid, 0)
	if hello.Tag != protocol.ReconnectSuccess || h.s.Stats().Attached != 2 || h.dials.Load() != 2 {
		t.Fatal("resume needed a fresh quota slot")
	}
}

func TestExpiredAuthorizerCannotUsePrunedRevocation(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var admissionDone <-chan struct{}
	h := newHarness(t, func(c *Config) {
		c.DialTimeout = 5 * time.Millisecond
		c.Authorizer = authorizeFunc(func(ctx context.Context, _ *http.Request, _ Endpoint) (Grant, error) {
			admissionDone = ctx.Done()
			close(entered)
			<-release
			return Grant{UserID: "user", LoginID: "login", ClientKind: "native", ClientID: "installation"}, nil
		})
	})
	go func() {
		h.s.connect(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
		close(done)
	}()
	<-entered
	h.s.RevokeUser("user")
	<-admissionDone
	h.s.mu.Lock()
	h.s.revokedUsers["user"] = revocation{epoch: h.s.epoch, expires: time.Now().Add(-time.Second)}
	h.s.mu.Unlock()
	h.s.sweep(h.s.cfg.Now(), 0)
	close(release)
	<-done
	if h.dials.Load() != 0 {
		t.Fatal("late authorizer escaped deadline after tombstone pruning")
	}
}

func TestAuditShutdownCountsUndeliveredEvents(t *testing.T) {
	entered := make(chan struct{})
	var calls atomic.Int32
	h := newHarness(t, func(c *Config) {
		c.AuditTimeout = 10 * time.Millisecond
		c.Audit = auditFunc(func(ctx context.Context, _ AuditEvent) error {
			if calls.Add(1) == 1 {
				close(entered)
			}
			<-ctx.Done()
			return ctx.Err()
		})
	})
	h.s.emit(AuditEvent{Kind: "test.first"})
	<-entered
	for range 3 {
		h.s.emit(AuditEvent{Kind: "test.queued"})
	}
	h.s.Close()
	select {
	case <-h.s.auditDone:
	case <-time.After(time.Second):
		t.Fatal("audit shutdown exceeded its budget")
	}
	h.s.emit(AuditEvent{Kind: "test.after_close"})
	if h.s.Stats().AuditLost != 5 {
		t.Fatalf("unreported audit loss: %+v", h.s.Stats())
	}
}
