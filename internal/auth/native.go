package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dotwaffle/sshpd/internal/nativeapi"
	"github.com/dotwaffle/sshpd/internal/store"
	"github.com/dotwaffle/sshpd/relay"
)

type approval struct {
	clientID, pollHash, secret string
	expires                    time.Time
	login                      store.Login
}

type ticket struct {
	loginID, destinationID string
	expires                time.Time
}

var errTarget = errors.New("destination unavailable")

func decodeNative(w http.ResponseWriter, r *http.Request, out any) error {
	if r.Method != http.MethodPost || r.Header.Get("Origin") != "" || r.Header.Get("Content-Type") != "application/json" {
		return nativeapi.ErrDenied
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return nativeapi.ErrDenied
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nativeapi.ErrDenied
	}
	return nil
}

func bearer(r *http.Request) (string, error) {
	if len(r.Header.Values("Authorization")) != 1 {
		return "", nativeapi.ErrDenied
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", nativeapi.ErrDenied
	}
	value := strings.TrimPrefix(header, "Bearer ")
	if !nativeapi.ValidID(value, 52) {
		return "", nativeapi.ErrDenied
	}
	return value, nil
}

func nativeJSON(w http.ResponseWriter, value any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(value)
}

// NativeHTTP implements proof-bound approval initiation, polling, and tickets.
// Browser approval uses the separate same-origin WebAuthn handler.
func (s *Service) NativeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var err error
	switch r.URL.Path {
	case "/native/login/start":
		err = s.startApproval(w, r)
	case "/native/login/poll":
		err = s.pollApproval(w, r)
	case "/native/ticket":
		err = s.issueTicket(w, r)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, nativeapi.ErrDenied), errors.Is(err, store.ErrDenied):
			status = http.StatusUnauthorized
		case errors.Is(err, relay.ErrLimit):
			status = http.StatusTooManyRequests
		case errors.Is(err, errTarget):
			status = http.StatusBadRequest
		}
		http.Error(w, "native admission unavailable", status)
		return
	}
}

func (s *Service) startApproval(w http.ResponseWriter, r *http.Request) error {
	var input nativeapi.Start
	if err := decodeNative(w, r, &input); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(input.PollHash)
	if !nativeapi.ValidID(input.ClientID, 26) || err != nil || len(decoded) != 32 {
		return nativeapi.ErrDenied
	}
	if err := s.Prune(r.Context(), time.Now()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.approvals) >= 1024 {
		return relay.ErrLimit
	}
	code := rand.Text()[:12]
	if _, exists := s.approvals[code]; exists {
		return relay.ErrLimit
	}
	expires := time.Now().Add(s.cfg.ApprovalTTL)
	s.approvals[code] = approval{clientID: input.ClientID, pollHash: strings.ToLower(input.PollHash), expires: expires}
	return nativeJSON(w, nativeapi.Approval{Code: code, URL: s.cfg.Origin + "/approve#" + code, ClientID: input.ClientID, Expires: expires})
}

func (s *Service) approvalInfo(code string) (approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.approvals[code]
	if !ok || !time.Now().Before(p.expires) || p.secret != "" {
		return approval{}, nativeapi.ErrDenied
	}
	return p, nil
}

// ApprovalInfo exposes only the code and installation that the user will approve.
func (s *Service) ApprovalInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Origin") != s.cfg.Origin || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "invalid approval request", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var input struct {
		Code string `json:"code"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		http.Error(w, "approval unavailable", http.StatusUnauthorized)
		return
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(w, "approval unavailable", http.StatusUnauthorized)
		return
	}
	p, err := s.approvalInfo(input.Code)
	if err != nil {
		http.Error(w, "approval unavailable", http.StatusUnauthorized)
		return
	}
	_ = nativeJSON(w, nativeapi.Approval{Code: input.Code, ClientID: p.clientID, Expires: p.expires})
}

func (s *Service) completeApproval(ctx context.Context, code string, input store.LoginInput) (store.Login, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.approvals[code]
	if !ok || p.secret != "" || !time.Now().Before(p.expires) {
		return store.Login{}, nativeapi.ErrDenied
	}
	input.Kind, input.ClientID = "native", p.clientID
	login, err := s.store.CreateLogin(ctx, input)
	if err != nil {
		return store.Login{}, err
	}
	p.login, p.secret = login, input.Secret
	s.approvals[code] = p
	return login, nil
}

func (s *Service) pollApproval(w http.ResponseWriter, r *http.Request) error {
	var input nativeapi.Poll
	if err := decodeNative(w, r, &input); err != nil {
		return err
	}
	if !nativeapi.ValidID(input.Proof, 52) {
		return nativeapi.ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.approvals[input.Code]
	if !ok || !time.Now().Before(p.expires) || subtle.ConstantTimeCompare([]byte(nativeapi.Hash(input.Proof)), []byte(p.pollHash)) != 1 {
		return nativeapi.ErrDenied
	}
	if p.secret == "" {
		w.WriteHeader(http.StatusAccepted)
		return nil
	}
	login, err := s.store.AdmissionByID(r.Context(), p.login.ID, time.Now())
	delete(s.approvals, input.Code)
	if err != nil || login.Kind != "native" || login.ClientID != p.clientID {
		return nativeapi.ErrDenied
	}
	return nativeJSON(w, nativeapi.Grant{Secret: p.secret, ClientID: p.clientID, Expires: login.Expires})
}

func (s *Service) nativeLogin(ctx context.Context, r *http.Request) (store.Login, error) {
	secret, err := bearer(r)
	if err != nil {
		return store.Login{}, err
	}
	login, err := s.store.Admission(ctx, secret, time.Now())
	if err != nil {
		return store.Login{}, err
	}
	if login.Kind != "native" {
		return store.Login{}, nativeapi.ErrDenied
	}
	return login, nil
}

func (s *Service) issueTicket(w http.ResponseWriter, r *http.Request) error {
	var input nativeapi.Target
	if err := decodeNative(w, r, &input); err != nil {
		return err
	}
	login, err := s.nativeLogin(r.Context(), r)
	if err != nil {
		return err
	}
	if s.cfg.Resolver == nil {
		return nativeapi.ErrDenied
	}
	target, err := s.cfg.Resolver.Resolve(r.Context(), relay.Endpoint{Host: input.Host, Port: input.Port})
	if err != nil {
		return errTarget
	}
	secret := rand.Text() + rand.Text()
	expires := minTime(time.Now().Add(s.cfg.TicketTTL), login.Expires)
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, t := range s.tickets {
		if !time.Now().Before(t.expires) {
			delete(s.tickets, hash)
		}
	}
	if len(s.tickets) >= 4096 {
		return relay.ErrLimit
	}
	s.tickets[nativeapi.Hash(secret)] = ticket{loginID: login.ID, destinationID: target.ID, expires: expires}
	return nativeJSON(w, nativeapi.Ticket{Secret: secret, Expires: expires})
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) admitTicket(ctx context.Context, r *http.Request, requested relay.Endpoint) (relay.Grant, error) {
	secret, err := bearer(r)
	if err != nil || s.cfg.Resolver == nil {
		return relay.Grant{}, relay.ErrDenied
	}
	hash := nativeapi.Hash(secret)
	s.mu.Lock()
	t, ok := s.tickets[hash]
	delete(s.tickets, hash)
	s.mu.Unlock()
	if !ok || !time.Now().Before(t.expires) {
		return relay.Grant{}, relay.ErrDenied
	}
	target, err := s.cfg.Resolver.Resolve(ctx, requested)
	if err != nil || target.ID != t.destinationID {
		return relay.Grant{}, relay.ErrDenied
	}
	login, err := s.store.AdmissionByID(ctx, t.loginID, time.Now())
	if err != nil || login.Kind != "native" {
		return relay.Grant{}, relay.ErrDenied
	}
	return relay.Grant{UserID: login.UserID, LoginID: login.ID, ClientKind: "native", ClientID: login.ClientID, DestinationID: t.destinationID}, nil
}

// NativeLogout revokes one native login. The caller closes its relay streams.
func (s *Service) NativeLogout(w http.ResponseWriter, r *http.Request) (string, error) {
	var input struct{}
	if err := decodeNative(w, r, &input); err != nil {
		return "", err
	}
	secret, err := bearer(r)
	if err != nil {
		return "", err
	}
	id, err := s.store.NativeLogoutIdentity(r.Context(), secret)
	if err != nil {
		return "", err
	}
	if err := s.store.Logout(r.Context(), id); err != nil {
		return "", err
	}
	return id, nil
}
