// Package egress decides where the server may connect on behalf of a
// client (reliable TCP and glue UDP). The tunnel is for the internet:
// the VPS itself, its private networks (cloud VPC, docker) and special
// addresses are off limits.
package egress

import (
	"fmt"
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

	mu    sync.RWMutex
	own   map[string]bool // addresses of local interfaces
	extra map[string]bool // own addresses not on an interface (1:1 NAT)
}

// AddOwn adds addresses of this server that are not on any interface:
// in clouds with 1:1 NAT (AWS, GCP, Yandex Cloud, Oracle) the public IP
// only exists in the provider's NAT, so New can't find it.
func (p *Policy) AddOwn(ips ...net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.extra == nil {
		p.extra = make(map[string]bool)
	}
	for _, ip := range ips {
		p.extra[ip.String()] = true
	}
}

// New loads the host's own addresses. It fails if they can't be read:
// without them the server's own public IP would not be blocked.
// Call Refresh from time to time, addresses can change (DHCP).
func New(allowPrivate bool) (*Policy, error) {
	p := &Policy{AllowPrivate: allowPrivate}
	if err := p.Refresh(); err != nil {
		return nil, err
	}
	return p, nil
}

// Refresh reloads the addresses of all local interfaces. On error the
// previous list is kept, so a temporary failure doesn't unblock them.
func (p *Policy) Refresh() error {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("read interface addresses: %w", err)
	}
	own := make(map[string]bool)
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			own[ipn.IP.String()] = true
		}
	}
	if len(own) == 0 {
		return fmt.Errorf("no interface addresses found")
	}
	p.mu.Lock()
	p.own = own
	p.mu.Unlock()
	return nil
}

// Translated IPv6 forms of IPv4 addresses: NAT64 (RFC 6052) carries the
// IPv4 address in the last 4 bytes, 6to4 (RFC 3056) in bytes 2..5.
var (
	nat64Prefix = mustCIDRs("64:ff9b::/96")[0]
	sixToFour   = mustCIDRs("2002::/16")[0]
)

// embeddedIPv4 returns the IPv4 address inside a NAT64 or 6to4 address,
// so 64:ff9b::7f00:1 is checked as 127.0.0.1.
func embeddedIPv4(ip net.IP) net.IP {
	switch {
	case nat64Prefix.Contains(ip):
		return net.IP(ip[12:16])
	case sixToFour.Contains(ip):
		return net.IP(ip[2:6])
	}
	return nil
}

// Allowed reports if the server may connect to ip, with a reason if not.
func (p *Policy) Allowed(ip net.IP) (bool, string) {
	if v4 := embeddedIPv4(ip); v4 != nil {
		if ok, reason := p.Allowed(v4); !ok {
			return false, reason + " (inside an IPv6 address)"
		}
	}
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
	own := p.own[ip.String()] || p.extra[ip.String()]
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
