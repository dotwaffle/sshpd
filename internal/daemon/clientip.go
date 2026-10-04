package daemon

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/dotwaffle/sshpd/internal/requestmeta"
)

func trusted(ip netip.Addr, proxies []netip.Prefix) bool {
	for _, proxy := range proxies {
		if proxy.Contains(ip) {
			return true
		}
	}
	return false
}

func forwardedClient(r *http.Request, proxies []netip.Prefix) requestmeta.Client {
	client := requestmeta.FromRequest(r)
	peer := requestmeta.Peer(r.RemoteAddr)
	if !trusted(peer, proxies) {
		return client
	}
	chain := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if chain == "" || len(chain) > 4096 {
		return client
	}
	hops := strings.Split(chain, ",")
	if len(hops) > 32 {
		return client
	}
	addresses := make([]netip.Addr, 0, len(hops))
	for _, hop := range hops {
		ip, err := netip.ParseAddr(strings.TrimSpace(hop))
		if err != nil || ip.Zone() != "" {
			return client
		}
		addresses = append(addresses, ip.Unmap())
	}
	for i := len(addresses) - 1; i >= 0 && trusted(peer, proxies); i-- {
		peer = addresses[i]
	}
	client.IP = peer.String()
	return client
}
