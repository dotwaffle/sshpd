package agent

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"
)

// ServerStatus describes a server known to this agent without exposing credentials.
type ServerStatus struct {
	Server   string    `json:"server"`
	LoggedIn bool      `json:"logged_in"`
	Pending  bool      `json:"pending"`
	Expires  time.Time `json:"expires"`
}

// AllStatus lists servers in origin order, including expired and logged-out entries.
type AllStatus struct {
	ClientID string         `json:"client_id"`
	Servers  []ServerStatus `json:"servers"`
}

// LogoutResult reports whether a server's native login was revoked.
type LogoutResult struct {
	Server    string `json:"server"`
	LoggedOut bool   `json:"logged_out"`
}

func (s *Service) serveAll(w http.ResponseWriter, r *http.Request, input Request) {
	if input != (Request{}) {
		http.Error(w, "all-server requests must not select a server or login", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var result any
	if r.URL.Path == "/status/all" {
		result = s.statusAll()
	} else {
		result = s.logoutAll(ctx)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		s.cfg.Logger.DebugContext(ctx, "agent response interrupted")
	}
}

func (s *Service) statusAll() AllStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := AllStatus{ClientID: s.cfg.ClientID, Servers: make([]ServerStatus, 0, len(s.generation))}
	now := time.Now()
	for _, origin := range slices.Sorted(maps.Keys(s.generation)) {
		g, ok := s.grants[origin]
		p, pending := s.pending[origin]
		result.Servers = append(result.Servers, ServerStatus{
			Server: origin, LoggedIn: ok && now.Before(g.Expires),
			Pending: pending && now.Before(p.approval.Expires), Expires: g.Expires,
		})
	}
	return result
}

func (s *Service) logoutAll(ctx context.Context) []LogoutResult {
	s.mu.Lock()
	origins := slices.Sorted(maps.Keys(s.generation))
	grants := maps.Clone(s.grants)
	// Fence every pending or in-flight approval before starting remote requests.
	for _, origin := range origins {
		s.generation[origin]++
		delete(s.pending, origin)
	}
	s.mu.Unlock()

	results := make([]LogoutResult, len(origins))
	var workers sync.WaitGroup
	// The agent admits at most 16 servers. One slow relay must not block the rest.
	for i, origin := range origins {
		workers.Go(func() {
			g, ok := grants[origin]
			results[i] = LogoutResult{Server: origin, LoggedOut: !ok || s.revoke(ctx, origin, g) == nil}
		})
	}
	workers.Wait()
	return results
}
