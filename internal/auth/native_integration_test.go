package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/client"
	"github.com/dotwaffle/sshpd/internal/agent"
	"github.com/dotwaffle/sshpd/internal/nativeapi"
	"github.com/dotwaffle/sshpd/internal/store"
	"github.com/dotwaffle/sshpd/relay"
)

func TestNativePasskeyAgentTicketResumeAndScopedLogout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	t.Cleanup(cancel)
	logger := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "admission.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	backend, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	var peers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, acceptErr := backend.Accept()
			if acceptErr != nil {
				return
			}
			dials.Add(1)
			peers.Go(func() { defer conn.Close(); _, _ = io.Copy(conn, conn) })
		}
	}()
	t.Cleanup(func() { backend.Close(); <-accepted; peers.Wait() })
	host, portText, err := net.SplitHostPort(backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	address := relay.Endpoint{Host: host, Port: uint16(port)}
	registry, err := relay.NewRegistry([]relay.Destination{{ID: "home", Aliases: []relay.Endpoint{{Host: "home"}}, Backend: address}})
	if err != nil {
		t.Fatal(err)
	}
	var auth *Service
	var core *relay.Server
	var resumes atomic.Int32
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/native/logout":
			id, logoutErr := auth.NativeLogout(w, r)
			if logoutErr != nil {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			core.RevokeLogin(id)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/native/"):
			auth.NativeHTTP(w, r)
		default:
			if r.URL.Path == "/v4/reconnect" {
				resumes.Add(1)
				if r.Header.Get("Authorization") != "" {
					t.Error("resume reused ticket")
				}
			}
			core.ServeHTTP(w, r)
		}
	}))
	var hijackedMu sync.Mutex
	var hijacked net.Conn
	h.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateHijacked {
			hijackedMu.Lock()
			hijacked = c
			hijackedMu.Unlock()
		}
	}
	h.StartTLS()
	t.Cleanup(h.Close)
	// Route the fixture's domain to its local TLS listener. The httptest
	// certificate covers example.com, so no verification bypass is needed.
	physicalAddress := strings.TrimPrefix(h.URL, "https://")
	h.URL = strings.Replace(h.URL, "127.0.0.1", "example.com", 1)
	transport, ok := h.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected test transport")
	}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", physicalAddress)
	}
	auth, err = New(Config{Origin: h.URL, RPID: "example.com", LoginTTL: time.Hour, CeremonyTTL: time.Minute, Logger: logger, Resolver: registry}, db)
	if err != nil {
		t.Fatal(err)
	}
	core, err = relay.New(ctx, relay.Config{Authorizer: auth, Resolver: registry, Logger: logger, Limits: relay.Limits{Retention: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	u, err := db.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	k := newFixtureKey(t, "integration-native-key")
	fixtureEnrollment(t, auth, db, u, k, 0x45)
	loginAgent := func() (*httptest.Server, nativeapi.Ticket) {
		t.Helper()
		s, newErr := agent.New(agent.Config{ClientID: rand.Text(), HTTPClient: h.Client(), Logger: logger})
		if newErr != nil {
			t.Fatal(newErr)
		}
		local := httptest.NewServer(s)
		t.Cleanup(local.Close)
		request := agent.Request{Server: h.URL, Target: nativeapi.Target{Host: "home"}}
		var p nativeapi.Approval
		if _, startErr := nativeapi.Post(ctx, local.Client(), local.URL, "/login/start", request, "", &p); startErr != nil {
			t.Fatal(startErr)
		}
		if w := nativeApprove(t, auth, p.Code, k, u.ID); w.Code != http.StatusOK { //nolint:contextcheck // Browser fixtures use the testing lifetime, independent of the helper context.
			t.Fatal("passkey approval failed", w.Code)
		}
		request.Code = p.Code
		var status agent.Status
		if _, pollErr := nativeapi.Post(ctx, local.Client(), local.URL, "/login/poll", request, "", &status); pollErr != nil || !status.LoggedIn {
			t.Fatal("agent did not store login", pollErr)
		}
		var ticket nativeapi.Ticket
		if _, ticketErr := nativeapi.Post(ctx, local.Client(), local.URL, "/ticket", request, "", &ticket); ticketErr != nil {
			t.Fatal(ticketErr)
		}
		return local, ticket
	}
	open := func(ticket nativeapi.Ticket) *client.Conn {
		t.Helper()
		c, openErr := client.Open(ctx, client.Config{URL: h.URL, HTTPClient: h.Client(), Destination: relay.Endpoint{Host: "home"}, Header: http.Header{"Authorization": []string{"Bearer " + ticket.Secret}}, Logger: logger, MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, ResumeWindow: time.Second})
		if openErr != nil {
			t.Fatal(openErr)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	echo := func(c *client.Conn, text string) {
		t.Helper()
		if _, writeErr := c.Write([]byte(text)); writeErr != nil {
			t.Fatal(writeErr)
		}
		data := make([]byte, len(text))
		if _, readErr := io.ReadFull(c, data); readErr != nil || string(data) != text {
			t.Fatal("echo failed", readErr)
		}
		if flushErr := c.Flush(ctx); flushErr != nil {
			t.Fatal(flushErr)
		}
	}
	local, ticket := loginAgent()
	first := open(ticket)
	echo(first, "before agent loss")
	local.Close()
	hijackedMu.Lock()
	if hijacked == nil {
		hijackedMu.Unlock()
		t.Fatal("no hijacked connection")
	}
	_ = hijacked.Close()
	hijackedMu.Unlock()
	echo(first, "after agent loss and network reconnect")
	if dials.Load() != 1 || resumes.Load() == 0 {
		t.Fatal("resume opened a new backend or did not reconnect", dials.Load(), resumes.Load())
	}
	secondAgent, secondTicket := loginAgent()
	second := open(secondTicket)
	echo(second, "second login")
	if _, err = nativeapi.Post(ctx, secondAgent.Client(), secondAgent.URL, "/logout", agent.Request{Server: h.URL}, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = second.Read(make([]byte, 1)); err == nil {
		t.Fatal("logout left its stream open")
	}
	echo(first, "first login remains")
	keys, err := db.UserByName(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := db.RemoveCredential(ctx, u.ID, keys.Credentials[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		core.RevokeLogin(id)
	}
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("key revocation left stream open")
	}
}

func TestNativeUncollectedApprovalCleanupAndFailedAssertion(t *testing.T) {
	s, db := testAuth(t, false)
	u, err := db.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	k := newFixtureKey(t, "cleanup-key")
	fixtureEnrollment(t, s, db, u, k, 0x45)
	p, _ := nativeFixture(t, s)
	w := authRequest(t, s, "/auth/native/begin", beginInput{Name: "alice", Approval: p.Code}, "")
	var o options
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	wrong := newFixtureKey(t, "cleanup-key")
	if w = authRequest(t, s, "/auth/native/finish", wrong.assertion(t, o, s.cfg.Origin, s.cfg.RPID, 0x05, u.ID), o.Ceremony); w.Code != http.StatusUnauthorized {
		t.Fatal("invalid signature approved")
	}
	if s.approvals[p.Code].secret != "" {
		t.Fatal("failed assertion created grant")
	}
	if w = nativeApprove(t, s, p.Code, k, u.ID); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	entry := s.approvals[p.Code]
	if err := s.Prune(t.Context(), entry.expires.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.NativeLogoutIdentity(t.Context(), entry.secret); err == nil {
		t.Fatal("uncollected grant retained")
	}
}
