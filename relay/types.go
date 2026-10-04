package relay

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Relay admission and lifecycle errors.
var (
	ErrDenied   = errors.New("relay admission denied")
	ErrLimit    = errors.New("relay capacity reached")
	ErrGone     = errors.New("relay session gone")
	ErrProtocol = errors.New("invalid relay protocol")
)

// Grant identifies a successful admission. IDs are opaque, stable ownership keys.
// LoginID enables logout and passkey revocation without closing other logins.
type Grant struct {
	UserID, LoginID, ClientKind, ClientID string
	// DestinationID binds a native ticket to a canonical destination.
	// An empty value permits any destination approved by the resolver.
	DestinationID string
}

// Authorizer checks a fresh admission, including credential expiry and tickets.
// Resume uses the SID capability and never calls Admit.
// The authorizer must deny revoked credentials on subsequent admissions.
type Authorizer interface {
	Admit(context.Context, *http.Request, Endpoint) (Grant, error)
}

// Dialer opens a backend TCP connection and must honor context cancellation.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// AuditEvent describes a lifecycle event. SessionID is an audit correlation ID,
// never the protocol SID. No payloads or credentials belong in an audit event.
type AuditEvent struct {
	Time                    time.Time
	Kind, SessionID, Reason string
	Grant                   Grant
	DestinationID           string
	Requested, Backend      Endpoint
	Received, Sent          uint64
}

// AuditSink records unsampled audit events. Record must honor ctx and support
// concurrent calls. Success means acceptance by the sink, not crash durability.
type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

// Limits controls session retention and memory. Zero fields select defaults.
// Negative ReplacementAge disables fresh-connection replacement cleanup.
type Limits struct {
	Sessions, SessionsPerUser, ReplayBytes, ReplayBudget int
	Retention, EvictionAge, ReplacementAge               time.Duration
	OldestFirst                                          bool
	PressureHigh, PressureLow                            float64
}

// Config supplies relay policy and dependencies. MemoryLimit is a finite Go
// memory limit in bytes, or zero for unlimited. MemoryUsage must be fast and
// return Go-managed memory usage, not a replay-buffer count.
type Config struct {
	Authorizer                                     Authorizer
	Resolver                                       Resolver
	Dialer                                         Dialer
	Audit                                          AuditSink
	Logger                                         *slog.Logger
	Limits                                         Limits
	MemoryLimit                                    uint64
	MemoryUsage                                    func() uint64
	Origins                                        []string
	Now                                            func() time.Time
	DialTimeout, WriteTimeout, BackendWriteTimeout time.Duration
	AuditTimeout                                   time.Duration
	AuditQueue                                     int
	StrictAudit                                    bool
	MaxDialing                                     int
}

// Stats reports aggregate counters without principal or protocol session IDs.
type Stats struct {
	Attached, Detached, Dialing int
	ReplayCapacity              int
	AuditLost                   uint64
}
