package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/transport"
)

// clientKeyEnv holds the private key, so the tray doesn't have to write
// it into client-config.json.
const clientKeyEnv = "SPLICERTC_CLIENT_KEY"

// errNoClientKey: without a key the server reads our first frames as an
// auth response, counts a failed login and soon bans the IP.
var errNoClientKey = errors.New("no client key: set client_key_file or client_key in the config, " +
	"or the " + clientKeyEnv + " environment variable (make a key with cmd/genkey)")

// loadClientKey returns the key seed. The environment variable wins over
// client_key_file, which wins over client_key.
func loadClientKey(env, file, inline string) ([]byte, error) {
	var seed []byte
	var err error
	switch {
	case env != "":
		seed, err = auth.DecodeKey(env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", clientKeyEnv, err)
		}
	case file != "":
		// checks the length itself
		return auth.LoadClientKey(file)
	case inline != "":
		seed, err = auth.DecodeKey(inline)
		if err != nil {
			return nil, fmt.Errorf("client_key: %w", err)
		}
	default:
		return nil, errNoClientKey
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("client key: expected a %d-byte seed, got %d bytes", ed25519.SeedSize, len(seed))
	}
	return seed, nil
}

// resolver turns server host names into IPs once at startup. The tray
// routes the server IP around the tunnel; with round-robin DNS a second
// lookup could return an IP that isn't routed around, and the tunnel
// would loop into itself.
type resolver struct {
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	ips    map[string]net.IP // host -> IP, so the same host gives the same IP
}

func newResolver() *resolver {
	return &resolver{lookup: net.DefaultResolver.LookupIPAddr, ips: make(map[string]net.IP)}
}

// resolve returns addr with the host replaced by its IP, and the host
// name ("" if addr already had an IP).
func (r *resolver) resolve(addr string) (ipAddr, name string, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("server address %q: %w", addr, err)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return addr, "", nil
	}
	ip, ok := r.ips[host]
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), transport.DialTimeout)
		defer cancel()
		addrs, err := r.lookup(ctx, host)
		if err != nil {
			return "", "", fmt.Errorf("resolve %s: %w", host, err)
		}
		if ip = pickIP(addrs); ip == nil {
			return "", "", fmt.Errorf("resolve %s: no addresses", host)
		}
		r.ips[host] = ip
	}
	return net.JoinHostPort(ip.String(), port), host, nil
}

// pickIP prefers IPv4: the tunnel only carries IPv4, and an IPv6 server
// address would need its own bypass route.
func pickIP(addrs []net.IPAddr) net.IP {
	for _, a := range addrs {
		if ip4 := a.IP.To4(); ip4 != nil {
			return ip4
		}
	}
	if len(addrs) > 0 {
		return addrs[0].IP
	}
	return nil
}

// endpoint is a server address resolved at startup and how to check the
// server's certificate there.
type endpoint struct {
	addr string // ip:port
	dc   transport.DialConfig
}

// endpoint resolves addr. The certificate is checked against serverName,
// or against the host name from addr if serverName is empty.
func (r *resolver) endpoint(addr, serverName string, insecure bool) (endpoint, error) {
	ipAddr, name, err := r.resolve(addr)
	if err != nil {
		return endpoint{}, err
	}
	if serverName == "" {
		serverName = name
	}
	return endpoint{addr: ipAddr, dc: transport.DialConfig{ServerName: serverName, Insecure: insecure}}, nil
}

// vpnAddresses returns the client (.2) and gateway (.1) addresses of the
// vpn subnet. It must be the same subnet as on the server.
func vpnAddresses(subnet string) (local, gateway netip.Addr, err error) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return local, gateway, fmt.Errorf("vpn_subnet: %w", err)
	}
	if !p.Addr().Is4() || p.Bits() > 30 {
		return local, gateway, fmt.Errorf("vpn_subnet %s: need an IPv4 subnet of /30 or bigger", subnet)
	}
	gateway = p.Masked().Addr().Next()
	return gateway.Next(), gateway, nil
}
