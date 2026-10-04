package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/dotwaffle/sshpd/protocol"
)

type reservation struct {
	grant                   Grant
	target                  Target
	victim                  *session
	cancel                  context.CancelFunc
	canceled                bool
	epoch, destinationEpoch uint64
}

type revocation struct {
	epoch   uint64
	expires time.Time
}

// Server owns backend connections independently of WebSocket request lifetimes.
// Close invalidates all SIDs and closes every backend connection.
type Server struct {
	auditMu                     sync.Mutex
	auditClosed                 bool
	mu                          sync.Mutex
	cfg                         Config
	sessions                    map[string]*session
	pending                     map[*reservation]bool
	epoch, destinationEpoch     uint64
	revokedUsers, revokedLogins map[string]revocation
	allocated                   int
	closed                      chan struct{}
	stop                        context.CancelFunc
	auditQueue                  chan AuditEvent
	auditDone                   chan struct{}
	auditLost                   atomic.Uint64
	pressureHold                time.Time
	pressureCredit              uint64
	lastMemoryUsed              uint64
	pressureBlocked             bool
}

// New validates dependencies and starts bounded maintenance and audit workers.
// Canceling ctx closes the server. The caller must also call Close.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if err := defaults(&cfg); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{cfg: cfg, sessions: make(map[string]*session), pending: make(map[*reservation]bool),
		revokedUsers: make(map[string]revocation), revokedLogins: make(map[string]revocation),
		closed: make(chan struct{}), stop: cancel, auditQueue: make(chan AuditEvent, cfg.AuditQueue), auditDone: make(chan struct{})}
	go s.auditLoop(ctx)
	go s.maintenance(ctx)
	return s, nil
}

func defaults(c *Config) error {
	if c.MemoryLimit >= math.MaxInt64 {
		c.MemoryLimit = 0
	}
	if c.Authorizer == nil || c.Resolver == nil {
		return errors.New("relay requires an authorizer and resolver")
	}
	if c.Dialer == nil {
		c.Dialer = &net.Dialer{}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.BackendWriteTimeout == 0 {
		c.BackendWriteTimeout = 30 * time.Second
	}
	if c.AuditTimeout == 0 {
		c.AuditTimeout = 5 * time.Second
	}
	if c.AuditQueue == 0 {
		c.AuditQueue = 1024
	}
	if c.MaxDialing == 0 {
		c.MaxDialing = 64
	}
	l := &c.Limits
	if l.Sessions == 0 {
		l.Sessions = 1024
	}
	if l.SessionsPerUser == 0 {
		l.SessionsPerUser = 32
	}
	if l.ReplayBytes == 0 {
		l.ReplayBytes = 1 << 20
	}
	if l.ReplayBudget == 0 {
		l.ReplayBudget = 64 << 20
		if c.MemoryLimit > 0 && c.MemoryLimit < math.MaxInt64 {
			l.ReplayBudget = int(min(uint64(l.ReplayBudget), c.MemoryLimit/10))
		}
	}
	if l.Retention == 0 {
		l.Retention = 15 * time.Minute
	}
	if l.EvictionAge == 0 {
		l.EvictionAge = time.Minute
	}
	if l.ReplacementAge == 0 {
		l.ReplacementAge = time.Minute
	}
	if l.PressureHigh == 0 {
		l.PressureHigh = .8
	}
	if l.PressureLow == 0 {
		l.PressureLow = .7
	}
	if l.Sessions < 1 || l.SessionsPerUser < 1 || l.ReplayBytes < 1 || l.ReplayBudget < 1 || l.Retention < 0 || l.EvictionAge < 0 || math.IsNaN(l.PressureLow) || math.IsNaN(l.PressureHigh) || l.PressureLow <= 0 || l.PressureLow >= l.PressureHigh || l.PressureHigh >= 1 || c.MaxDialing < 1 || c.AuditQueue < 1 || c.DialTimeout < 0 || c.WriteTimeout < 0 || c.BackendWriteTimeout < 0 || c.AuditTimeout < 0 {
		return errors.New("invalid relay limits")
	}
	c.Origins = append([]string(nil), c.Origins...)
	for _, origin := range c.Origins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || strings.ContainsAny(origin, "*?") {
			return errors.New("origins must be exact scheme and host values")
		}
	}
	return nil
}

// ServeHTTP handles only /v4/connect and /v4/reconnect.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validOrigin(r) || !hasSubprotocol(r, "ssh") {
		http.Error(w, "invalid websocket handshake", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/v4/connect":
		s.connect(w, r)
	case "/v4/reconnect":
		s.reconnect(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if slices.Contains(s.cfg.Origins, origin) {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.Host == r.Host && (u.Scheme == "http" || u.Scheme == "https")
}

func hasSubprotocol(r *http.Request, wanted string) bool {
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for p := range strings.SplitSeq(value, ",") {
			if strings.TrimSpace(p) == wanted {
				return true
			}
		}
	}
	return false
}

func requestEndpoint(r *http.Request) (Endpoint, error) {
	q := r.URL.Query()
	if len(q["host"]) != 1 || len(q["port"]) > 1 {
		return Endpoint{}, ErrDestination
	}
	port := uint64(22)
	if text := q.Get("port"); text != "" {
		n, err := strconv.ParseUint(text, 10, 16)
		if err != nil || n == 0 {
			return Endpoint{}, ErrDestination
		}
		port = n
	}
	return (Endpoint{Host: q.Get("host"), Port: uint16(port)}).Normalize()
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	requested, err := requestEndpoint(r)
	if err != nil {
		http.Error(w, "invalid destination", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.DialTimeout)
	defer cancel()
	s.mu.Lock()
	res := &reservation{cancel: cancel, epoch: s.epoch, destinationEpoch: s.destinationEpoch}
	s.mu.Unlock()
	grant, err := s.cfg.Authorizer.Admit(ctx, r, requested)
	if err != nil || ctx.Err() != nil || grant.UserID == "" || grant.LoginID == "" || grant.ClientKind == "" || grant.ClientID == "" {
		http.Error(w, "admission denied", http.StatusUnauthorized)
		return
	}
	target, err := s.cfg.Resolver.Resolve(ctx, requested)
	if err != nil || ctx.Err() != nil || target.ID == "" || grant.DestinationID != "" && grant.DestinationID != target.ID {
		http.Error(w, "destination not configured", http.StatusForbidden)
		return
	}
	target.Backend, err = target.Backend.Normalize()
	if err != nil {
		http.Error(w, "invalid backend", http.StatusForbidden)
		return
	}
	res.grant, res.target = grant, target
	err = s.reserve(ctx, res)
	if err != nil {
		http.Error(w, "relay capacity reached", http.StatusTooManyRequests)
		return
	}
	defer s.release(res)
	backend, err := s.cfg.Dialer.DialContext(ctx, "tcp", target.Backend.Address())
	if err != nil || ctx.Err() != nil {
		if backend != nil {
			_ = backend.Close()
		}
		http.Error(w, "backend unavailable", http.StatusBadGateway)
		return
	}
	var token [32]byte
	_, _ = rand.Read(token[:])
	readCtx, readCancel := context.WithCancel(context.WithoutCancel(r.Context()))
	p := &session{sid: hex.EncodeToString(token[:]), id: rand.Text(), grant: grant, target: target, requested: requested, backend: backend, wake: make(chan struct{}), stop: readCancel}
	if err = s.commit(ctx, res, p); err != nil {
		readCancel()
		_ = backend.Close()
		http.Error(w, "relay capacity reached", http.StatusTooManyRequests)
		return
	}
	go s.readBackend(readCtx, p)
	// Audit admission before exposing its SID. Strict failures close the backend.
	s.mu.Lock()
	event := s.eventLocked(p, "session.start", "")
	s.mu.Unlock()
	if s.cfg.StrictAudit {
		if err = s.record(ctx, event); err != nil {
			s.terminate(p, "audit_failure")
			http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
			return
		}
	} else {
		s.emit(event)
	}
	ws, err := s.accept(w, r)
	if err != nil {
		s.terminate(p, "handshake_failed")
		return
	}
	a, err := s.attach(p, ws, 0, false)
	if err != nil {
		_ = ws.CloseNow()
		return
	}
	s.run(context.WithoutCancel(r.Context()), p, a, protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte(p.sid)})
}

func (s *Server) reconnect(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ack, err := strconv.ParseUint(q.Get("ack"), 10, 64)
	if err != nil || len(q["sid"]) != 1 || len(q["ack"]) != 1 {
		http.Error(w, "invalid resume", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	p := s.sessions[q.Get("sid")]
	s.mu.Unlock()
	if p == nil {
		http.Error(w, "session gone", http.StatusGone)
		return
	}
	ws, err := s.accept(w, r)
	if err != nil {
		return
	}
	a, err := s.attach(p, ws, ack, true)
	if err != nil {
		_ = ws.Close(websocket.StatusPolicyViolation, "resume rejected")
		return
	}
	s.mu.Lock()
	received := p.received
	event := s.eventLocked(p, "session.resume", "")
	s.mu.Unlock()
	s.emit(event)
	s.run(context.WithoutCancel(r.Context()), p, a, protocol.Packet{Tag: protocol.ReconnectSuccess, Position: received})
}

func (s *Server) accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	// Exact origin validation runs before Accept. Pattern matching is not used.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"ssh"}, InsecureSkipVerify: true})
	if err == nil {
		c.SetReadLimit(protocol.MaxArray + 6)
	}
	return c, err
}

func (s *Server) admissionValidLocked(ctx context.Context, res *reservation) bool {
	return ctx.Err() == nil && !res.canceled && res.destinationEpoch == s.destinationEpoch &&
		s.revokedUsers[res.grant.UserID].epoch <= res.epoch && s.revokedLogins[res.grant.LoginID].epoch <= res.epoch
}

func (s *Server) reserve(ctx context.Context, res *reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.admissionValidLocked(ctx, res) {
		return ErrDenied
	}
	select {
	case <-s.closed:
		return ErrGone
	default:
	}
	if len(s.pending) >= s.cfg.MaxDialing {
		return ErrLimit
	}
	if s.pressureBlocked {
		return ErrLimit
	}
	grant, target := res.grant, res.target
	total, user := len(s.sessions)+len(s.pending), 0
	claimed := make(map[*session]bool)
	for _, p := range s.sessions {
		if p.grant.UserID == grant.UserID {
			user++
		}
	}
	for pending := range s.pending {
		if pending.grant.UserID == grant.UserID {
			user++
		}
		if pending.victim != nil && s.replaceable(pending.victim, pending.grant, pending.target, s.cfg.Now()) && s.sessions[pending.victim.sid] == pending.victim {
			total--
			if pending.victim.grant.UserID == grant.UserID {
				user--
			}
			claimed[pending.victim] = true
		}
	}
	if total >= s.cfg.Limits.Sessions || user >= s.cfg.Limits.SessionsPerUser {
		for _, p := range s.sessions {
			if !claimed[p] && s.replaceable(p, grant, target, s.cfg.Now()) && (res.victim == nil || p.detached.Before(res.victim.detached)) {
				res.victim = p
			}
		}
		if res.victim == nil {
			return ErrLimit
		}
	}
	s.pending[res] = true
	return nil
}

func (s *Server) release(res *reservation) { s.mu.Lock(); delete(s.pending, res); s.mu.Unlock() }

func (s *Server) replaceable(p *session, g Grant, t Target, now time.Time) bool {
	return s.cfg.Limits.ReplacementAge >= 0 && p.attached == nil && !p.detached.IsZero() && now.Sub(p.detached) > s.cfg.Limits.ReplacementAge && p.grant.UserID == g.UserID && p.grant.ClientKind == g.ClientKind && p.grant.ClientID == g.ClientID && p.target.ID == t.ID
}

func (s *Server) commit(ctx context.Context, res *reservation, p *session) error {
	s.mu.Lock()
	if !s.admissionValidLocked(ctx, res) {
		s.mu.Unlock()
		return ErrDenied
	}
	select {
	case <-s.closed:
		s.mu.Unlock()
		return ErrGone
	default:
	}
	var victims []*session
	user := 0
	for _, old := range s.sessions {
		if old.grant.UserID == p.grant.UserID {
			user++
		}
		if s.replaceable(old, p.grant, p.target, s.cfg.Now()) {
			victims = append(victims, old)
		}
	}
	if len(s.sessions)-len(victims) >= s.cfg.Limits.Sessions || user-len(victims) >= s.cfg.Limits.SessionsPerUser {
		s.mu.Unlock()
		return ErrLimit
	}
	delete(s.pending, res)
	for _, old := range victims {
		s.removeLocked(old, "replaced")
	}
	p.detached = s.cfg.Now()
	s.sessions[p.sid] = p
	s.mu.Unlock()
	for _, old := range victims {
		closeSession(old)
	}
	return nil
}

// RevokeUser closes all sessions owned by the user.
func (s *Server) RevokeUser(userID string) {
	s.revoke(userID, true)
}

// RevokeLogin closes only sessions created under the specified login.
func (s *Server) RevokeLogin(loginID string) {
	s.revoke(loginID, false)
}
func (s *Server) revoke(id string, user bool) {
	s.mu.Lock()
	s.epoch++
	mark := revocation{epoch: s.epoch, expires: time.Now().Add(s.cfg.DialTimeout)}
	reason := "login_revoked"
	if user {
		s.revokedUsers[id] = mark
		reason = "user_revoked"
	} else {
		s.revokedLogins[id] = mark
	}
	match := func(g Grant) bool {
		if user {
			return g.UserID == id
		}
		return g.LoginID == id
	}
	var victims []*session
	for _, p := range s.sessions {
		if match(p.grant) {
			s.removeLocked(p, reason)
			victims = append(victims, p)
		}
	}
	for res := range s.pending {
		if match(res.grant) {
			res.canceled = true
			res.cancel()
		}
	}
	s.mu.Unlock()
	for _, p := range victims {
		closeSession(p)
	}
}

// ReconcileDestinations closes removed or retargeted sessions when immediate is
// true. With draining, it leaves existing sessions and their resume SIDs intact.
// The resolver must publish its new snapshot before this call.
func (s *Server) ReconcileDestinations(ctx context.Context, immediate bool) error {
	s.mu.Lock()
	s.destinationEpoch++
	for res := range s.pending {
		res.canceled = true
		res.cancel()
	}
	list := make([]*session, 0, len(s.sessions))
	for _, p := range s.sessions {
		list = append(list, p)
	}
	s.mu.Unlock()
	if !immediate {
		return nil
	}
	for _, p := range list {
		target, err := s.cfg.Resolver.Resolve(ctx, p.requested)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || target != p.target {
			s.terminate(p, "destination_removed")
		}
	}
	return nil
}

// Stats returns current aggregate resource use.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := Stats{Dialing: len(s.pending), ReplayCapacity: s.allocated, AuditLost: s.auditLost.Load()}
	for _, p := range s.sessions {
		if p.attached == nil {
			v.Detached++
		} else {
			v.Attached++
		}
	}
	return v
}

// Close rejects admissions, cancels dials, and closes all sessions.
// It waits for the bounded audit shutdown drain before returning.
func (s *Server) Close() error {
	s.mu.Lock()
	select {
	case <-s.closed:
		s.mu.Unlock()
		<-s.auditDone
		return nil
	default:
		close(s.closed)
	}
	var list []*session
	for _, p := range s.sessions {
		s.removeLocked(p, "server_closed")
		list = append(list, p)
	}
	for res := range s.pending {
		res.cancel()
	}
	s.mu.Unlock()
	for _, p := range list {
		closeSession(p)
	}
	s.stop()
	<-s.auditDone
	return nil
}

func writePacket(ctx context.Context, ws *websocket.Conn, p protocol.Packet, timeout time.Duration) error {
	b, err := protocol.Encode(p)
	if err != nil {
		return fmt.Errorf("encode relay command: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return ws.Write(ctx, websocket.MessageBinary, b)
}
