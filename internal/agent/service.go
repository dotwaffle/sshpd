// Package agent holds native login grants in memory behind a private socket.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/dotwaffle/sshpd/internal/nativeapi"
)

// ErrLogin signals that explicit login is required for a fresh connection.
var ErrLogin = errors.New("login required; run sshpc login")

// Config supplies the installation identity and remote transport.
type Config struct {
	ClientID      string
	HTTPClient    *http.Client
	Logger        *slog.Logger
	AllowInsecure bool
}

type pending struct {
	approval   nativeapi.Approval
	proof      string
	generation uint64
}

// Service retains bearers and approval polling proofs without writing them out.
type Service struct {
	mu         sync.Mutex
	cfg        Config
	grants     map[string]nativeapi.Grant
	pending    map[string]pending
	generation map[string]uint64
}

// New initializes an empty agent. Restarting loses every admission credential.
func New(cfg Config) (*Service, error) {
	if !nativeapi.ValidID(cfg.ClientID, 26) || cfg.Logger == nil {
		return nil, errors.New("invalid agent configuration")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Service{cfg: cfg, grants: make(map[string]nativeapi.Grant), pending: make(map[string]pending), generation: make(map[string]uint64)}, nil
}

// Request selects a public relay and an optional approval or destination.
type Request struct {
	Server string           `json:"server"`
	Code   string           `json:"code,omitempty"`
	Target nativeapi.Target `json:"target,omitzero"`
}

// Status reports identity and expiry without returning a bearer or polling proof.
type Status struct {
	ClientID string    `json:"client_id"`
	LoggedIn bool      `json:"logged_in"`
	Expires  time.Time `json:"expires"`
}

// ServeHTTP exposes login, ticket, logout, and non-secret status over a private socket.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Origin") != "" {
		http.Error(w, "invalid agent request", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var input Request
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		http.Error(w, "invalid agent request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid agent request", http.StatusBadRequest)
		return
	}
	origin, err := nativeapi.Origin(input.Server, s.cfg.AllowInsecure)
	if err != nil {
		http.Error(w, "invalid server origin", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var result any
	switch r.URL.Path {
	case "/login/start":
		result, err = s.start(ctx, origin)
	case "/login/poll":
		var ready bool
		ready, err = s.poll(ctx, origin, input.Code)
		if err == nil && !ready {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		result = s.status(origin)
	case "/ticket":
		result, err = s.ticket(ctx, origin, input.Target)
	case "/logout":
		err = s.logout(ctx, origin)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	case "/status":
		result = s.status(origin)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if errors.Is(err, ErrLogin) || errors.Is(err, nativeapi.ErrDenied) {
			http.Error(w, ErrLogin.Error(), http.StatusUnauthorized)
		} else {
			http.Error(w, "agent operation failed", http.StatusBadGateway)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(result); encodeErr != nil {
		s.cfg.Logger.DebugContext(ctx, "agent response interrupted")
	}
}

func (s *Service) start(ctx context.Context, origin string) (nativeapi.Approval, error) {
	s.mu.Lock()
	if _, known := s.generation[origin]; !known && len(s.generation) >= 16 {
		s.mu.Unlock()
		return nativeapi.Approval{}, errors.New("agent server limit reached")
	}
	s.generation[origin]++
	generation := s.generation[origin]
	delete(s.pending, origin)
	s.mu.Unlock()
	proof := rand.Text() + rand.Text()
	var approval nativeapi.Approval
	_, err := nativeapi.Post(ctx, s.cfg.HTTPClient, origin, "/native/login/start", nativeapi.Start{ClientID: s.cfg.ClientID, PollHash: nativeapi.Hash(proof)}, "", &approval)
	if err != nil {
		return nativeapi.Approval{}, err
	}
	if approval.ClientID != s.cfg.ClientID || !nativeapi.ValidID(approval.Code, 12) || approval.URL != origin+"/approve#"+approval.Code || !time.Now().Before(approval.Expires) {
		return nativeapi.Approval{}, nativeapi.ErrTransport
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation[origin] != generation {
		return nativeapi.Approval{}, nativeapi.ErrDenied
	}
	s.pending[origin] = pending{approval: approval, proof: proof, generation: generation}
	return approval, nil
}

func (s *Service) poll(ctx context.Context, origin, code string) (bool, error) {
	s.mu.Lock()
	p, ok := s.pending[origin]
	s.mu.Unlock()
	if !ok || code != p.approval.Code || !time.Now().Before(p.approval.Expires) {
		return false, nativeapi.ErrDenied
	}
	var grant nativeapi.Grant
	status, err := nativeapi.Post(ctx, s.cfg.HTTPClient, origin, "/native/login/poll", nativeapi.Poll{Code: code, Proof: p.proof}, "", &grant)
	if err != nil {
		return false, err
	}
	if status == http.StatusAccepted {
		return false, nil
	}
	if !nativeapi.ValidID(grant.Secret, 52) || grant.ClientID != s.cfg.ClientID || !time.Now().Before(grant.Expires) {
		return false, nativeapi.ErrTransport
	}
	s.mu.Lock()
	current, exists := s.pending[origin]
	if !exists || current.generation != p.generation || s.generation[origin] != p.generation {
		s.mu.Unlock()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = nativeapi.Post(cleanup, s.cfg.HTTPClient, origin, "/native/logout", struct{}{}, grant.Secret, nil)
		return false, nativeapi.ErrDenied
	}
	s.grants[origin] = grant
	delete(s.pending, origin)
	s.mu.Unlock()
	s.cfg.Logger.InfoContext(ctx, "native login stored")
	return true, nil
}

func (s *Service) status(origin string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[origin]
	return Status{ClientID: s.cfg.ClientID, LoggedIn: ok && time.Now().Before(g.Expires), Expires: g.Expires}
}

func (s *Service) grant(origin string) (nativeapi.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[origin]
	if !ok || !time.Now().Before(g.Expires) {
		return nativeapi.Grant{}, ErrLogin
	}
	return g, nil
}

func (s *Service) discard(origin, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants[origin].Secret == secret {
		delete(s.grants, origin)
	}
}

func (s *Service) ticket(ctx context.Context, origin string, target nativeapi.Target) (nativeapi.Ticket, error) {
	g, err := s.grant(origin)
	if err != nil {
		return nativeapi.Ticket{}, err
	}
	var ticket nativeapi.Ticket
	_, err = nativeapi.Post(ctx, s.cfg.HTTPClient, origin, "/native/ticket", target, g.Secret, &ticket)
	if errors.Is(err, nativeapi.ErrDenied) {
		s.discard(origin, g.Secret)
		return nativeapi.Ticket{}, ErrLogin
	}
	if err != nil {
		return nativeapi.Ticket{}, err
	}
	if !nativeapi.ValidID(ticket.Secret, 52) || !time.Now().Before(ticket.Expires) || ticket.Expires.After(g.Expires) {
		return nativeapi.Ticket{}, nativeapi.ErrTransport
	}
	return ticket, nil
}

func (s *Service) logout(ctx context.Context, origin string) error {
	s.mu.Lock()
	if _, known := s.generation[origin]; known {
		s.generation[origin]++
	}
	delete(s.pending, origin)
	g, ok := s.grants[origin]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	_, err := nativeapi.Post(ctx, s.cfg.HTTPClient, origin, "/native/logout", struct{}{}, g.Secret, nil)
	if err == nil || errors.Is(err, nativeapi.ErrDenied) {
		s.discard(origin, g.Secret)
		return nil
	}
	return err
}
