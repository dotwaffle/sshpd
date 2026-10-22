package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/internal/nativeapi"
)

func agentAllRequest(t *testing.T, s *Service, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAllStatusAndLogoutPartialFailure(t *testing.T) {
	first, second := fixtureRemote(t), fixtureRemote(t)
	second.id = first.id
	s := fixtureService(t, first)
	fixtureAgentLogin(t, s, first)
	fixtureAgentLogin(t, s, second)
	// Expired logins must remain available for revocation.
	g := s.grants[first.server.URL]
	g.Expires = time.Now().Add(-time.Minute)
	s.grants[first.server.URL] = g
	w := agentAllRequest(t, s, "/status/all", `{}`)
	var status AllStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || w.Code != http.StatusOK {
		t.Fatal("status failed", err, w.Code)
	}
	if status.ClientID != first.id || len(status.Servers) != 2 || status.Servers[0].Server >= status.Servers[1].Server {
		t.Fatal("status omitted servers or did not sort them")
	}
	for _, item := range status.Servers {
		if item.LoggedIn != (item.Server == second.server.URL) || item.Pending {
			t.Fatal("incorrect login state")
		}
	}
	for _, secret := range []string{first.secret, second.secret, first.proofHash, second.proofHash} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("status exposed a credential")
		}
	}
	first.logoutStatus.Store(http.StatusServiceUnavailable)
	w = agentAllRequest(t, s, "/logout/all", `{}`)
	var results []LogoutResult
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil || w.Code != http.StatusOK || len(results) != 2 {
		t.Fatal("logout results missing", err, w.Code)
	}
	for _, result := range results {
		if result.LoggedOut != (result.Server == second.server.URL) {
			t.Fatal("incorrect logout result")
		}
	}
	if _, ok := s.grants[first.server.URL]; !ok || second.logouts.Load() != 1 || len(s.grants) != 1 {
		t.Fatal("partial failure lost retry credentials or skipped another server")
	}
	first.logoutStatus.Store(0)
	for _, result := range s.logoutAll(t.Context()) {
		if !result.LoggedOut {
			t.Fatal("retry failed")
		}
	}
	if len(s.grants) != 0 || first.logouts.Load() != 1 || second.logouts.Load() != 1 {
		t.Fatal("retry did not revoke only the remaining grant")
	}
}

func TestAllLogoutFencesLateApproval(t *testing.T) {
	f := fixtureRemote(t)
	f.entered, f.release = make(chan struct{}), make(chan struct{})
	s := fixtureService(t, f)
	p, err := s.start(t.Context(), f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if status := s.statusAll(); len(status.Servers) != 1 || !status.Servers[0].Pending {
		t.Fatal("pending approval missing from status")
	}
	done := make(chan error, 1)
	go func() { _, err := s.poll(t.Context(), f.server.URL, p.Code); done <- err }()
	select {
	case <-f.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("poll did not reach server")
	}
	results := s.logoutAll(t.Context())
	close(f.release)
	if err := <-done; !errors.Is(err, nativeapi.ErrDenied) {
		t.Fatal("late approval accepted", err)
	}
	if len(results) != 1 || !results[0].LoggedOut || s.status(f.server.URL).LoggedIn || f.logouts.Load() != 1 {
		t.Fatal("late grant was not revoked")
	}
}

func TestAllEndpointsRejectSelectedRequests(t *testing.T) {
	s := fixtureService(t, fixtureRemote(t))
	for _, path := range []string{"/status/all", "/logout/all"} {
		for _, body := range []string{`{"server":"https://relay.example"}`, `{"code":"unexpected"}`, `{"target":{"host":"home","port":22}}`} {
			t.Run(path+body, func(t *testing.T) {
				if w := agentAllRequest(t, s, path, body); w.Code != http.StatusBadRequest {
					t.Fatal("selected request accepted as all-server operation")
				}
			})
		}
	}
	for _, path := range []string{"/login/start", "/login/poll", "/ticket", "/status", "/logout"} {
		if w := agentAllRequest(t, s, path, `{}`); w.Code != http.StatusBadRequest {
			t.Fatal("single-server endpoint accepted missing origin", path)
		}
	}
	if w := agentAllRequest(t, s, "/logout/all", `{}`); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("empty logout failed")
	}
	if status := s.statusAll(); status.Servers == nil || !slices.Equal(status.Servers, []ServerStatus{}) {
		t.Fatal("empty status is not an empty list")
	}
}
