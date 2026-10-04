// Package requestmeta carries validated transport metadata between handlers.
package requestmeta

import (
	"context"
	"net"
	"net/http"
	"net/netip"
)

// Client contains canonical IP addresses, without ports or forwarding headers.
type Client struct {
	IP, Peer string
}

type clientKey struct{}

// FromContext returns validated addresses when a server attached them.
func FromContext(ctx context.Context) (Client, bool) {
	client, ok := ctx.Value(clientKey{}).(Client)
	return client, ok
}

// WithClient attaches addresses that the server has validated.
func WithClient(ctx context.Context, client Client) context.Context {
	return context.WithValue(ctx, clientKey{}, client)
}

// FromRequest returns validated metadata or the direct transport peer.
func FromRequest(r *http.Request) Client {
	if client, ok := FromContext(r.Context()); ok {
		return client
	}
	ip := Peer(r.RemoteAddr)
	if !ip.IsValid() {
		return Client{}
	}
	return Client{IP: ip.String(), Peer: ip.String()}
}

// Peer parses a transport address and removes IPv4 mapping and IPv6 zones.
func Peer(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.WithZone("").Unmap()
}
