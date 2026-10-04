package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/internal/nativeapi"
	"github.com/dotwaffle/sshpd/relay"
)

func nativeRequest(t *testing.T, s *Service, path string, input any, secret string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	w := httptest.NewRecorder()
	s.NativeHTTP(w, r)
	return w
}

func nativeFixture(t *testing.T, s *Service) (nativeapi.Approval, string) {
	t.Helper()
	proof := rand.Text() + rand.Text()
	w := nativeRequest(t, s, "/native/login/start", nativeapi.Start{ClientID: rand.Text(), PollHash: nativeapi.Hash(proof)}, "")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	var approval nativeapi.Approval
	if err := json.Unmarshal(w.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	return approval, proof
}

func nativeApprove(t *testing.T, s *Service, code string, k fixtureKey, userID string) *httptest.ResponseRecorder {
	t.Helper()
	w := authRequest(t, s, "/auth/native/begin", beginInput{Name: "alice", Approval: code}, "")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var o options
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	return authRequest(t, s, "/auth/native/finish", k.assertion(t, o, s.cfg.Origin, s.cfg.RPID, 0x05, userID), o.Ceremony)
}

func TestNativeApprovalProofAndTicketBinding(t *testing.T) {
	s, db := testAuth(t, false)
	u, err := db.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	k := newFixtureKey(t, "native-key")
	fixtureEnrollment(t, s, db, u, k, 0x45)
	s.cfg.Resolver, err = relay.NewRegistry([]relay.Destination{
		{ID: "home", Aliases: []relay.Endpoint{{Host: "home"}, {Host: "alias"}}, Backend: relay.Endpoint{Host: "127.0.0.1"}},
		{ID: "other", Aliases: []relay.Endpoint{{Host: "other"}}, Backend: relay.Endpoint{Host: "127.0.0.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, proof := nativeFixture(t, s)
	if w := nativeRequest(t, s, "/native/login/poll", nativeapi.Poll{Code: p.Code, Proof: proof}, ""); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	if w := nativeApprove(t, s, p.Code, k, u.ID); w.Code != http.StatusOK || len(w.Result().Cookies()) != 0 {
		t.Fatal("approval failed or set a browser cookie", w.Code)
	}
	if w := nativeRequest(t, s, "/native/login/poll", nativeapi.Poll{Code: p.Code, Proof: rand.Text() + rand.Text()}, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("wrong proof accepted")
	}
	w := nativeRequest(t, s, "/native/login/poll", nativeapi.Poll{Code: p.Code, Proof: proof}, "")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	var grant nativeapi.Grant
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.ClientID != p.ClientID || !nativeapi.ValidID(grant.Secret, 52) {
		t.Fatal("grant binding missing")
	}
	if w = nativeRequest(t, s, "/native/login/poll", nativeapi.Poll{Code: p.Code, Proof: proof}, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("poll replay accepted")
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect", http.NoBody)
	r.AddCookie(&http.Cookie{Name: loginCookie, Value: grant.Secret})
	if _, err := s.Login(t.Context(), r); err == nil {
		t.Fatal("native bearer accepted as browser cookie")
	}
	getTicket := func() string {
		t.Helper()
		w := nativeRequest(t, s, "/native/ticket", nativeapi.Target{Host: "home"}, grant.Secret)
		if w.Code != http.StatusOK {
			t.Fatal(w.Code)
		}
		var ticket nativeapi.Ticket
		if err := json.Unmarshal(w.Body.Bytes(), &ticket); err != nil {
			t.Fatal(err)
		}
		return ticket.Secret
	}
	admit := func(secret, host string) error {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect", http.NoBody)
		r.Header.Set("Authorization", "Bearer "+secret)
		_, err := s.Admit(t.Context(), r, relay.Endpoint{Host: host})
		return err
	}
	if err := admit(grant.Secret, "home"); err == nil {
		t.Fatal("long-lived native bearer used as an admission ticket")
	}
	secret := getTicket()
	if err := admit(secret, "alias"); err != nil {
		t.Fatal(err)
	}
	if err := admit(secret, "home"); err == nil {
		t.Fatal("ticket replay accepted")
	}
	if err := admit(getTicket(), "other"); err == nil {
		t.Fatal("ticket used for another destination")
	}
	secret = getTicket()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if admit(secret, "home") == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("ticket was not consumed atomically", accepted.Load())
	}
	s.cfg.TicketTTL = time.Nanosecond
	if err := admit(getTicket(), "home"); err == nil {
		t.Fatal("expired ticket admitted")
	}
	s.cfg.TicketTTL = 30 * time.Second
	secret = getTicket()
	if err := db.ChangeUser(t.Context(), u.ID, "disable"); err != nil {
		t.Fatal(err)
	}
	if admit(secret, "home") == nil {
		t.Fatal("ticket admitted disabled user")
	}
}

func TestNativeApprovalExpiryAndCeremonySeparation(t *testing.T) {
	s, db := testAuth(t, false)
	u, err := db.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	k := newFixtureKey(t, "expiry-key")
	fixtureEnrollment(t, s, db, u, k, 0x45)
	p, proof := nativeFixture(t, s)
	w := authRequest(t, s, "/auth/native/begin", beginInput{Name: "alice", Approval: p.Code}, "")
	var o options
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if w = authRequest(t, s, "/auth/login/finish", k.assertion(t, o, s.cfg.Origin, s.cfg.RPID, 0x05, u.ID), o.Ceremony); w.Code != http.StatusUnauthorized {
		t.Fatal("native ceremony used for browser login")
	}
	s.mu.Lock()
	entry := s.approvals[p.Code]
	entry.expires = time.Now().Add(-time.Second)
	s.approvals[p.Code] = entry
	s.mu.Unlock()
	if w = nativeRequest(t, s, "/native/login/poll", nativeapi.Poll{Code: p.Code, Proof: proof}, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("expired approval poll accepted")
	}
	if w = authRequest(t, s, "/auth/native/begin", beginInput{Name: "alice", Approval: p.Code}, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("expired approval authenticated")
	}
	if err := s.Prune(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(s.approvals) != 0 {
		t.Fatal("expired approval retained")
	}
}
