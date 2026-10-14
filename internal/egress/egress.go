// Package egress decides where the server may connect on behalf of a
// client (reliable TCP and glue UDP). The tunnel is for the internet:
// the VPS itself, its private networks (cloud VPC, docker) and special
// addresses are off limits.
package egress

import (
	"net"
	"sync"
)

// Private ranges that are not the internet. net.IP.IsPrivate covers
// RFC 1918 and fc00::/7; CGNAT (100.64.0.0/10) is used for internal
// networks by some clouds and VPNs.
var extraPrivate = mustCIDRs("100.64.0.0/10", "198.18.0.0/15")

// PrivateCIDRs are the IPv4 private ranges, also used for the iptables
// rules of the vpn channel.
var PrivateCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "198.18.0.0/15"}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// Policy checks destination addresses. The zero value blocks private
// ranges and knows no own addresses; use New.
type Policy struct {
	AllowPrivate bool

	mu  sync.RWMutex
	own map[string]bool // addresses of this host
}

// New loads the host's own addresses. Call Refresh from time to time if
// addresses can change (DHCP, new interfaces).
func New(allowPrivate bool) *Policy {
	p := &Policy{AllowPrivate: allowPrivate}
	p.Refresh()
	return p
}

// Refresh reloads the addresses of all local interfaces.
func (p *Policy) Refresh() {
	own := make(map[string]bool)
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				own[ipn.IP.String()] = true
			}
		}
	}
	p.mu.Lock()
	p.own = own
	p.mu.Unlock()
}

// Allowed reports if the server may connect to ip, with a reason if not.
func (p *Policy) Allowed(ip net.IP) (bool, string) {
	switch {
	case ip == nil:
		return false, "not an IP address"
	case ip.IsUnspecified():
		return false, "unspecified address"
	case ip.IsLoopback():
		return false, "loopback address"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return false, "link-local address (cloud metadata lives here)"
	case ip.IsMulticast(), ip.Equal(net.IPv4bcast):
		return false, "multicast/broadcast address"
	}
	p.mu.RLock()
	own := p.own[ip.String()]
	p.mu.RUnlock()
	if own {
		return false, "address of the server itself"
	}
	if !p.AllowPrivate && isPrivate(ip) {
		return false, "private network (set allow_private_destinations to allow)"
	}
	return true, ""
}

func isPrivate(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	for _, n := range extraPrivate {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
