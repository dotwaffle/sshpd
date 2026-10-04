package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/internal/nativeapi"
)

type remoteFixture struct {
	server                      *httptest.Server
	id, code, proofHash, secret string
	ticketStatus                atomic.Int32
	logoutStatus                atomic.Int32
	logouts                     atomic.Int32
	entered, release            chan struct{}
}

func fixtureRemote(t *testing.T) *remoteFixture {
	t.Helper()
	f := &remoteFixture{id: rand.Text(), code: rand.Text()[:12], secret: rand.Text() + rand.Text()}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/native/login/start":
			var input nativeapi.Start
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.ClientID != f.id {
				t.Error("invalid approval initiation")
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			f.proofHash = input.PollHash
			_ = json.NewEncoder(w).Encode(nativeapi.Approval{ClientID: f.id, Code: f.code, URL: f.server.URL + "/approve#" + f.code, Expires: time.Now().Add(time.Minute)})
		case "/native/login/poll":
			var input nativeapi.Poll
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Code != f.code || nativeapi.Hash(input.Proof) != f.proofHash {
				t.Error("polling proof missing")
				http.Error(w, "invalid", http.StatusUnauthorized)
				return
			}
			if f.entered != nil {
				close(f.entered)
				<-f.release
			}
			_ = json.NewEncoder(w).Encode(nativeapi.Grant{ClientID: f.id, Secret: f.secret, Expires: time.Now().Add(time.Hour)})
		case "/native/ticket":
			if r.Header.Get("Authorization") != "Bearer "+f.secret {
				t.Error("ticket missing private bearer")
			}
			if status := f.ticketStatus.Load(); status != 0 {
				http.Error(w, "opaque failure", int(status))
				return
			}
			_ = json.NewEncoder(w).Encode(nativeapi.Ticket{Secret: rand.Text() + rand.Text(), Expires: time.Now().Add(30 * time.Second)})
		case "/native/logout":
			if r.Header.Get("Authorization") != "Bearer "+f.secret {
				t.Error("logout missing private bearer")
			}
			if status := f.logoutStatus.Load(); status != 0 {
				w.WriteHeader(int(status))
				return
			}
			f.logouts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func fixtureService(t *testing.T, f *remoteFixture) *Service {
	t.Helper()
	s, err := New(Config{ClientID: f.id, HTTPClient: f.server.Client(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fixtureAgentLogin(t *testing.T, s *Service, f *remoteFixture) {
	t.Helper()
	p, err := s.start(t.Context(), f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := s.poll(t.Context(), f.server.URL, p.Code); err != nil || !ready {
		t.Fatal("login failed", err)
	}
}

func TestAgentKeepsSecretsAndPreservesGrantOnTargetOrCapacityFailure(t *testing.T) {
	f := fixtureRemote(t)
	s := fixtureService(t, f)
	fixtureAgentLogin(t, s, f)
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		f.ticketStatus.Store(int32(status))
		if _, err := s.ticket(t.Context(), f.server.URL, nativeapi.Target{Host: "home"}); err == nil || errors.Is(err, ErrLogin) {
			t.Fatalf("status %d lost login: %v", status, err)
		}
		if !s.status(f.server.URL).LoggedIn {
			t.Fatal("valid login discarded")
		}
	}
	f.ticketStatus.Store(0)
	if _, err := s.ticket(t.Context(), f.server.URL, nativeapi.Target{Host: "home"}); err != nil {
		t.Fatal(err)
	}
	status := s.status(f.server.URL)
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields["client_id"] != f.id {
		t.Fatal("status exposed unexpected fields")
	}
	f.ticketStatus.Store(http.StatusUnauthorized)
	if _, err := s.ticket(t.Context(), f.server.URL, nativeapi.Target{Host: "home"}); !errors.Is(err, ErrLogin) {
		t.Fatal(err)
	}
	if s.status(f.server.URL).LoggedIn {
		t.Fatal("revoked login retained")
	}
}

func TestAgentLogoutFencesLateApproval(t *testing.T) {
	f := fixtureRemote(t)
	f.entered, f.release = make(chan struct{}), make(chan struct{})
	s := fixtureService(t, f)
	p, err := s.start(t.Context(), f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.poll(t.Context(), f.server.URL, p.Code); done <- err }()
	select {
	case <-f.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("poll did not reach server")
	}
	if err := s.logout(t.Context(), f.server.URL); err != nil {
		t.Fatal(err)
	}
	close(f.release)
	if err := <-done; !errors.Is(err, nativeapi.ErrDenied) {
		t.Fatal("late approval accepted", err)
	}
	if s.status(f.server.URL).LoggedIn || f.logouts.Load() != 1 {
		t.Fatal("late grant was not revoked")
	}
	for range 30 {
		_ = s.logout(t.Context(), "https://unknown.example")
	}
	if len(s.generation) != 1 {
		t.Fatal("unknown logout consumed server slots")
	}
}

func TestAgentRestartLosesGrantAndExpiryAllowsLogout(t *testing.T) {
	f := fixtureRemote(t)
	s := fixtureService(t, f)
	fixtureAgentLogin(t, s, f)
	f.logoutStatus.Store(http.StatusInternalServerError)
	if err := s.logout(t.Context(), f.server.URL); err == nil || !s.status(f.server.URL).LoggedIn {
		t.Fatal("failed logout discarded credentials")
	}
	f.logoutStatus.Store(0)
	if fresh := fixtureService(t, f); fresh.status(f.server.URL).LoggedIn {
		t.Fatal("new agent retained credentials")
	}
	s.mu.Lock()
	g := s.grants[f.server.URL]
	g.Expires = time.Now().Add(-time.Second)
	s.grants[f.server.URL] = g
	s.mu.Unlock()
	if _, err := s.ticket(t.Context(), f.server.URL, nativeapi.Target{Host: "home"}); !errors.Is(err, ErrLogin) {
		t.Fatal("expired grant admitted", err)
	}
	if err := s.logout(t.Context(), f.server.URL); err != nil || f.logouts.Load() != 1 {
		t.Fatal("expired grant could not logout", err)
	}
}

func TestAgentRejectsRedirectedApproval(t *testing.T) {
	var contacted atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { contacted.Add(1); w.WriteHeader(http.StatusOK) }))
	t.Cleanup(target.Close)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	s, err := New(Config{ClientID: rand.Text(), HTTPClient: origin.Client(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.start(context.WithoutCancel(t.Context()), origin.URL); err == nil || contacted.Load() != 0 {
		t.Fatal("approval redirect followed")
	}
}
