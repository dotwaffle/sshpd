package daemon

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestForwardedClientTrustBoundary(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/48")}
	for _, test := range []struct {
		name, remote, want string
		forwarded          []string
	}{
		{"direct peer", "198.51.100.4:1000", "198.51.100.4", nil},
		{"untrusted spoof", "198.51.100.4:1000", "198.51.100.4", []string{"203.0.113.9"}},
		{"trusted proxy", "192.0.2.2:1000", "203.0.113.9", []string{"203.0.113.9"}},
		{"spoofed prefix", "192.0.2.2:1000", "198.51.100.4", []string{"203.0.113.9, 198.51.100.4"}},
		{"trusted chain", "192.0.2.2:1000", "203.0.113.9", []string{"203.0.113.9, 192.0.2.3"}},
		{"multiple fields", "192.0.2.2:1000", "203.0.113.9", []string{"203.0.113.9", "192.0.2.3"}},
		{"IPv6", "[2001:db8:1::2]:1000", "2001:db8:2::3", []string{"2001:db8:2::3"}},
		{"mapped peer", "[::ffff:192.0.2.2]:1000", "203.0.113.9", []string{"::ffff:203.0.113.9"}},
		{"all trusted", "192.0.2.2:1000", "192.0.2.4", []string{"192.0.2.4, 192.0.2.3"}},
		{"missing", "192.0.2.2:1000", "192.0.2.2", nil},
		{"empty hop", "192.0.2.2:1000", "192.0.2.2", []string{"203.0.113.9,"}},
		{"invalid hop", "192.0.2.2:1000", "192.0.2.2", []string{"unknown, 203.0.113.9"}},
		{"port forbidden", "192.0.2.2:1000", "192.0.2.2", []string{"203.0.113.9:22"}},
		{"zone forbidden", "192.0.2.2:1000", "192.0.2.2", []string{"fe80::1%eth0"}},
		{"too many hops", "192.0.2.2:1000", "192.0.2.2", []string{strings.Repeat("192.0.2.3,", 32) + "203.0.113.9"}},
		{"too large", "192.0.2.2:1000", "192.0.2.2", []string{strings.Repeat(" ", 4096) + "203.0.113.9"}},
		{"invalid remote", "unix", "", []string{"203.0.113.9"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = test.remote
			r.Header["X-Forwarded-For"] = test.forwarded
			r.Header.Set("X-Real-IP", "203.0.113.123")
			got := forwardedClient(r, proxies)
			if got.IP != test.want {
				t.Fatalf("client IP %q, want %q", got.IP, test.want)
			}
			peer := requestPeer(test.remote)
			if got.Peer != peer || r.RemoteAddr != test.remote {
				t.Fatalf("transport peer changed: %+v", got)
			}
			if direct := forwardedClient(r, nil); direct.IP != peer {
				t.Fatalf("default trusted headers: %+v", direct)
			}
		})
	}
}

func requestPeer(remote string) string {
	addr, err := netip.ParseAddrPort(remote)
	if err != nil {
		return ""
	}
	return addr.Addr().WithZone("").Unmap().String()
}

func TestTrustedProxyConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		cidrs []string
		valid bool
	}{
		{"default", nil, true},
		{"IPv4", []string{"192.0.2.2/24"}, true},
		{"IPv6", []string{"2001:db8::/32"}, true},
		{"plain IP", []string{"192.0.2.2"}, false},
		{"hostname", []string{"proxy.example"}, false},
		{"wildcard", []string{"*"}, false},
		{"mapped prefix", []string{"::ffff:192.0.2.0/120"}, false},
		{"too many", strings.Fields(strings.Repeat("192.0.2.0/24 ", 65)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{StateDir: "/tmp/state", PublicOrigin: "https://relay.example", RPID: "relay.example", TrustedProxies: test.cidrs}
			if err := cfg.validate(); (err == nil) != test.valid {
				t.Fatalf("configuration validation: %v", err)
			}
			if test.valid && len(test.cidrs) > 0 {
				next := cfg
				next.TrustedProxies = nil
				if err := next.validate(); err != nil || cfg.reloadCompatible(next) {
					t.Fatal("reload changed proxy trust")
				}
			}
		})
	}
}
