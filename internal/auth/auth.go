// Package auth verifies passkeys and admits browser relay connections.
package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/dotwaffle/sshpd/internal/store"
	"github.com/dotwaffle/sshpd/relay"
)

const (
	loginCookie   = "__Host-sshpd"
	profileCookie = "__Host-sshpd-profile"
)

// Config defines the public WebAuthn origin and bounded authentication lifetime.
type Config struct {
	Origin, RPID           string
	AllowNoUV              bool
	LoginTTL, CeremonyTTL  time.Duration
	Logger                 *slog.Logger
	ApprovalTTL, TicketTTL time.Duration
	Resolver               relay.Resolver
}

type user struct {
	store.User
	keys []webauthn.Credential
}

// WebAuthnID returns the stable account handle.
func (u user) WebAuthnID() []byte { return []byte(u.ID) }

// WebAuthnName returns the account name.
func (u user) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName returns the account name.
func (u user) WebAuthnDisplayName() string { return u.Name }

// WebAuthnCredentials returns the stored passkeys.
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.keys }

func userRecord(snapshot store.User) (user, error) {
	u := user{User: snapshot}
	if snapshot.Disabled {
		return user{}, store.ErrDenied
	}
	for _, key := range snapshot.Credentials {
		var credential webauthn.Credential
		if err := json.Unmarshal(key.Data, &credential); err != nil {
			return user{}, fmt.Errorf("decode stored credential: %w", err)
		}
		u.keys = append(u.keys, credential)
	}
	return u, nil
}

type ceremony struct {
	user           user
	session        webauthn.SessionData
	invitationHash []byte
	registration   bool
	expires        time.Time
	nativeCode     string
}

// Service owns transient, single-use ceremonies and persistent browser grants.
type Service struct {
	mu         sync.Mutex
	cfg        Config
	store      *store.Store
	wa         *webauthn.WebAuthn
	ceremonies map[string]ceremony
	approvals  map[string]approval
	tickets    map[string]ticket
}

// New validates the WebAuthn policy. UV is required unless explicitly disabled.
func New(cfg Config, db *store.Store) (*Service, error) {
	if cfg.ApprovalTTL == 0 {
		cfg.ApprovalTTL = 5 * time.Minute
	}
	if cfg.TicketTTL == 0 {
		cfg.TicketTTL = 30 * time.Second
	}
	if cfg.ApprovalTTL <= 0 || cfg.TicketTTL <= 0 {
		return nil, errors.New("invalid native authentication lifetimes")
	}
	if db == nil || cfg.LoginTTL <= 0 || cfg.CeremonyTTL <= 0 || cfg.Logger == nil {
		return nil, errors.New("invalid authentication configuration")
	}
	uv := protocol.VerificationRequired
	if cfg.AllowNoUV {
		uv = protocol.VerificationPreferred
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: cfg.RPID, RPDisplayName: "sshpd", RPOrigins: []string{cfg.Origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: uv},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.CeremonyTTL, TimeoutUVD: cfg.CeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.CeremonyTTL, TimeoutUVD: cfg.CeremonyTTL},
		}})
	if err != nil {
		return nil, fmt.Errorf("configure passkeys: %w", err)
	}
	return &Service{cfg: cfg, store: db, wa: wa, ceremonies: make(map[string]ceremony), approvals: make(map[string]approval), tickets: make(map[string]ticket)}, nil
}

// ServeHTTP accepts same-origin POST ceremonies and logout requests only.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Origin") != s.cfg.Origin || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "invalid request origin or content type", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var err error
	switch r.URL.Path {
	case "/auth/register/begin":
		err = s.begin(w, r, true)
	case "/auth/login/begin", "/auth/native/begin":
		err = s.begin(w, r, false)
	case "/auth/register/finish":
		err = s.finish(w, r, true)
	case "/auth/login/finish", "/auth/native/finish":
		err = s.finish(w, r, false)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		// Errors from parsers and storage can contain assertions or identifiers.
		s.cfg.Logger.WarnContext(r.Context(), "authentication rejected", slog.String("operation", r.URL.Path))
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
}

type beginInput struct {
	Name       string `json:"name"`
	Invitation string `json:"invitation"`
	Approval   string `json:"approval,omitempty"`
}

func (s *Service) begin(w http.ResponseWriter, r *http.Request, registration bool) error {
	var input beginInput
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	native := r.URL.Path == "/auth/native/begin"
	if native {
		if _, err := s.approvalInfo(input.Approval); err != nil {
			return err
		}
	} else if input.Approval != "" {
		return store.ErrDenied
	}
	var snapshot store.User
	var hash []byte
	var err error
	if registration {
		if len(input.Invitation) < 20 || len(input.Invitation) > 128 {
			return store.ErrDenied
		}
		digest := sha256.Sum256([]byte(input.Invitation))
		hash = digest[:]
		snapshot, err = s.store.Invitation(r.Context(), hash, time.Now())
	} else {
		snapshot, err = s.store.UserByName(r.Context(), input.Name)
	}
	if err != nil {
		return err
	}
	u, err := userRecord(snapshot)
	if err != nil {
		return err
	}
	var options any
	var session *webauthn.SessionData
	if registration {
		var creation *protocol.CredentialCreation
		creation, session, err = s.wa.BeginRegistration(u)
		if creation != nil {
			options = creation.Response
		}
	} else {
		var assertion *protocol.CredentialAssertion
		assertion, session, err = s.wa.BeginLogin(u)
		if assertion != nil {
			options = assertion.Response
		}
	}
	if err != nil {
		return err
	}
	id, err := s.remember(ceremony{user: u, session: *session, invitationHash: hash, registration: registration, expires: time.Now().Add(s.cfg.CeremonyTTL), nativeCode: input.Approval})
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(struct {
		ID      string `json:"ceremony"`
		Options any    `json:"publicKey"`
	}{id, options})
}

func (s *Service) remember(c ceremony) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	owned := 0
	for id, pending := range s.ceremonies {
		if !now.Before(pending.expires) {
			delete(s.ceremonies, id)
		} else if pending.user.ID == c.user.ID {
			owned++
		}
	}
	if len(s.ceremonies) >= 1024 || owned >= 8 {
		return "", relay.ErrLimit
	}
	id := rand.Text() + rand.Text()
	s.ceremonies[id] = c
	return id, nil
}

func (s *Service) take(id string, registration bool) (ceremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ceremonies[id]
	delete(s.ceremonies, id)
	if !ok || c.registration != registration || !time.Now().Before(c.expires) {
		return ceremony{}, store.ErrDenied
	}
	return c, nil
}

func (s *Service) finish(w http.ResponseWriter, r *http.Request, registration bool) error {
	c, err := s.take(r.Header.Get("X-Ceremony-ID"), registration)
	if err != nil {
		return err
	}
	if (c.nativeCode != "") != (r.URL.Path == "/auth/native/finish") {
		return store.ErrDenied
	}
	var credential *webauthn.Credential
	if registration {
		credential, err = s.wa.FinishRegistration(c.user, c.session, r)
	} else {
		credential, err = s.wa.FinishLogin(c.user, c.session, r)
	}
	if err != nil {
		return err
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	key := store.Credential{ID: credential.ID, Data: data}
	if registration {
		if err := s.store.Register(r.Context(), c.user.User, c.invitationHash, key, time.Now()); err != nil {
			return err
		}
		s.cfg.Logger.InfoContext(r.Context(), "passkey registered", slog.String("user_id", c.user.ID))
	} else {
		found := false
		for _, original := range c.user.Credentials {
			if bytes.Equal(original.ID, credential.ID) {
				key.Version = original.Version
				found = true
				break
			}
		}
		if !found {
			return store.ErrDenied
		}
		secret := rand.Text() + rand.Text()
		expires := time.Now().Add(s.cfg.LoginTTL)
		input := store.LoginInput{User: c.user.User, Credential: key, Secret: secret, Expires: expires}
		var login store.Login
		var loginErr error
		if c.nativeCode != "" {
			login, loginErr = s.completeApproval(r.Context(), c.nativeCode, input)
		} else {
			login, loginErr = s.store.CreateLogin(r.Context(), input)
		}
		if loginErr != nil {
			return loginErr
		}
		if credential.Authenticator.CloneWarning {
			s.cfg.Logger.WarnContext(r.Context(), "passkey counter warning", slog.String("user_id", c.user.ID))
		}
		if c.nativeCode == "" {
			s.setCookie(w, loginCookie, secret, expires)
			if _, profileErr := profileID(r); profileErr != nil {
				s.setCookie(w, profileCookie, rand.Text(), time.Now().Add(365*24*time.Hour))
			}
		}
		s.cfg.Logger.InfoContext(r.Context(), "login created", slog.String("user_id", login.UserID), slog.String("login_id", login.ID), slog.String("client_kind", login.Kind))
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(struct {
		OK bool `json:"ok"`
	}{true})
}

func (s *Service) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	//nolint:gosec // Terminal sends these Secure cookies from a different origin.
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode, Expires: expires})
}

func profileID(r *http.Request) (string, error) {
	profile, err := r.Cookie(profileCookie)
	if err != nil || len(profile.Value) != 26 {
		return "", store.ErrDenied
	}
	for _, c := range profile.Value {
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return "", store.ErrDenied
		}
	}
	return profile.Value, nil
}

// Login validates the current browser cookie without renewing its lifetime.
func (s *Service) Login(ctx context.Context, r *http.Request) (store.Login, error) {
	cookie, err := r.Cookie(loginCookie)
	if err != nil || len(cookie.Value) != 52 {
		return store.Login{}, relay.ErrDenied
	}
	login, err := s.store.Admission(ctx, cookie.Value, time.Now())
	if err != nil || login.Kind != "terminal" {
		return store.Login{}, relay.ErrDenied
	}
	return login, nil
}

// Admit checks a fresh browser grant. SID resumes bypass this method.
func (s *Service) Admit(ctx context.Context, r *http.Request, requested relay.Endpoint) (relay.Grant, error) {
	if len(r.Header.Values("Authorization")) != 0 {
		return s.admitTicket(ctx, r, requested)
	}
	login, err := s.Login(ctx, r)
	if err != nil {
		return relay.Grant{}, relay.ErrDenied
	}
	profile, err := profileID(r)
	if err != nil {
		return relay.Grant{}, relay.ErrDenied
	}
	return relay.Grant{UserID: login.UserID, LoginID: login.ID, ClientKind: "terminal", ClientID: profile}, nil
}

// Prune releases expired transient authentication state and undelivered grants.
func (s *Service) Prune(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	var orphaned []string
	for code, p := range s.approvals {
		if !now.Before(p.expires) {
			delete(s.approvals, code)
			if p.login.ID != "" {
				orphaned = append(orphaned, p.login.ID)
			}
		}
	}
	for id, c := range s.ceremonies {
		if !now.Before(c.expires) {
			delete(s.ceremonies, id)
		}
	}
	for hash, t := range s.tickets {
		if !now.Before(t.expires) {
			delete(s.tickets, hash)
		}
	}
	s.mu.Unlock()
	var result error
	for _, id := range orphaned {
		if err := s.store.Logout(ctx, id); err != nil && !errors.Is(err, store.ErrDenied) {
			result = errors.Join(result, err)
		}
	}
	return result
}

// Logout invalidates only the current login and clears its browser cookie.
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.Method != http.MethodPost || r.Header.Get("Origin") != s.cfg.Origin {
		return "", relay.ErrDenied
	}
	login, err := s.Login(r.Context(), r)
	if err != nil {
		return "", err
	}
	if err := s.store.Logout(r.Context(), login.ID); err != nil {
		return "", err
	}
	s.setCookie(w, loginCookie, "", time.Unix(1, 0))
	return login.ID, nil
}
