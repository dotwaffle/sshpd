// Package relay serves resumable corp-relay-v4 TCP sessions.
package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
)

// ErrDestination indicates that a requested host and port are not configured.
var ErrDestination = errors.New("destination not configured")

// Endpoint identifies an exact host and port. A zero port defaults to 22.
type Endpoint struct {
	Host string
	Port uint16
}

// Normalize returns a canonical IP literal or ASCII DNS name and explicit port.
func (e Endpoint) Normalize() (Endpoint, error) {
	h := e.Host
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		h = ip.Unmap().String()
	} else {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if h == "" || len(h) > 253 {
			return Endpoint{}, ErrDestination
		}
		for label := range strings.SplitSeq(h, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Endpoint{}, ErrDestination
			}
			for _, c := range label {
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
					return Endpoint{}, ErrDestination
				}
			}
		}
	}
	if e.Port == 0 {
		e.Port = 22
	}
	e.Host = h
	return e, nil
}

// Address formats an endpoint for net.Dial.
func (e Endpoint) Address() string { return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) }

// Target is a resolved, immutable destination snapshot pinned to a session.
type Target struct {
	ID      string
	Backend Endpoint
}

// Resolver maps an exact requested endpoint to an authorized backend.
type Resolver interface {
	Resolve(context.Context, Endpoint) (Target, error)
}

// Destination defines aliases for one stable destination ID and backend.
type Destination struct {
	ID      string
	Aliases []Endpoint
	Backend Endpoint
}

type registrySnapshot struct{ aliases map[Endpoint]Target }

// Registry provides atomic validated destination-list replacement.
type Registry struct {
	current atomic.Pointer[registrySnapshot]
}

// NewRegistry validates and installs the initial destination list.
func NewRegistry(destinations []Destination) (*Registry, error) {
	r := &Registry{}
	if err := r.Replace(destinations); err != nil {
		return nil, err
	}
	return r, nil
}

// Replace publishes a complete new list. Invalid lists preserve the old snapshot.
func (r *Registry) Replace(destinations []Destination) error {
	next := &registrySnapshot{aliases: make(map[Endpoint]Target)}
	ids := make(map[string]bool)
	for _, d := range destinations {
		if d.ID == "" || ids[d.ID] || len(d.Aliases) == 0 {
			return fmt.Errorf("duplicate or empty destination: %w", ErrDestination)
		}
		ids[d.ID] = true
		backend, err := d.Backend.Normalize()
		if err != nil {
			return fmt.Errorf("destination %s backend: %w", d.ID, err)
		}
		for _, alias := range d.Aliases {
			key, err := alias.Normalize()
			if err != nil {
				return fmt.Errorf("destination %s alias: %w", d.ID, err)
			}
			if _, exists := next.aliases[key]; exists {
				return fmt.Errorf("duplicate alias: %w", ErrDestination)
			}
			next.aliases[key] = Target{ID: d.ID, Backend: backend}
		}
	}
	r.current.Store(next)
	return nil
}

// Resolve returns only explicitly configured host and port pairs.
func (r *Registry) Resolve(ctx context.Context, e Endpoint) (Target, error) {
	if err := ctx.Err(); err != nil {
		return Target{}, err
	}
	key, err := e.Normalize()
	if err != nil {
		return Target{}, err
	}
	snapshot := r.current.Load()
	if snapshot != nil {
		if target, ok := snapshot.aliases[key]; ok {
			return target, nil
		}
	}
	return Target{}, ErrDestination
}
