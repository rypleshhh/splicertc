package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/egress"
)

// vpnNet is the address plan of the vpn channel: server is .1, the
// client is .2 of the subnet.
type vpnNet struct {
	subnet   *net.IPNet
	serverIP net.IP
	clientIP net.IP
}

// vpnSetup is what setupVPNTun needs from the config.
type vpnSetup struct {
	tunName      string
	mtu          int
	subnet       string
	egressIface  string // empty = auto-detect
	allowPrivate bool
	// own public IPs (1:1 NAT), the client must not reach them either
	publicIPs []net.IP
}

// runCmd runs a command and returns its stdout. A variable so tests can
// fake ip/iptables on any OS.
var runCmd = func(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// parseVPNSubnet checks the vpn_subnet value and returns the address plan.
func parseVPNSubnet(cidr string) (vpnNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return vpnNet{}, fmt.Errorf("parse vpn_subnet %q: %w", cidr, err)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return vpnNet{}, fmt.Errorf("vpn_subnet %q is not IPv4", cidr)
	}
	// 10.66.0.5/24 is most likely a typo, don't guess what was meant
	if !ip.Equal(ipnet.IP) {
		return vpnNet{}, fmt.Errorf("vpn_subnet %q has host bits set, use the network address (%s)", cidr, ipnet)
	}
	// need network, .1, .2 and broadcast, so at least a /30; a subnet
	// bigger than /8 would swallow half of the private ranges
	ones, _ := ipnet.Mask.Size()
	if ones > 30 || ones < 8 {
		return vpnNet{}, fmt.Errorf("vpn_subnet %q: prefix must be between /8 and /30", cidr)
	}
	return vpnNet{
		subnet:   ipnet,
		serverIP: net.IPv4(base[0], base[1], base[2], base[3]|1).To4(),
		clientIP: net.IPv4(base[0], base[1], base[2], base[3]|2).To4(),
	}, nil
}

// setupVPNTun creates and configures the server TUN device and the
// iptables rules. Linux only. cleanup removes the rules and closes the
// TUN, call it on shutdown.
func setupVPNTun(c vpnSetup) (dev tun.Device, n vpnNet, cleanup func(), err error) {
	n, err = parseVPNSubnet(c.subnet)
	if err != nil {
		return nil, vpnNet{}, nil, err
	}
	ones, _ := n.subnet.Mask.Size()

	dev, err = tun.CreateTUN(c.tunName, c.mtu)
	if err != nil {
		return nil, vpnNet{}, nil, fmt.Errorf("create TUN: %w", err)
	}
	actualName, _ := dev.Name()
	fail := func(err error) (tun.Device, vpnNet, func(), error) {
		dev.Close()
		return nil, vpnNet{}, nil, err
	}

	if _, err := runCmd("ip", "addr", "add", fmt.Sprintf("%s/%d", n.serverIP, ones), "dev", actualName); err != nil {
		return fail(fmt.Errorf("ip addr add: %w", err))
	}
	if _, err := runCmd("ip", "link", "set", "dev", actualName, "up"); err != nil {
		return fail(fmt.Errorf("ip link set up: %w", err))
	}

	// can't set this from inside docker, /proc/sys is read-only there
	if cur, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil {
		return fail(fmt.Errorf("read ip_forward: %w", err))
	} else if strings.TrimSpace(string(cur)) != "1" {
		return fail(fmt.Errorf(
			"net.ipv4.ip_forward is off, run on the host (not in docker):\n" +
				"  sudo sysctl -w net.ipv4.ip_forward=1\n" +
				"  echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-dormtun.conf"))
	}

	egressIface := c.egressIface
	if egressIface == "" {
		egressIface, err = detectEgressIface()
		if err != nil {
			return fail(fmt.Errorf("auto-detect egress interface failed, pass -egress-iface explicitly: %w", err))
		}
		log.Printf("vpn: auto-detected egress interface: %s", egressIface)
	}

	bin := detectIptables()
	log.Printf("vpn: using %s", bin)
	fw := newVPNFirewall(bin, n.subnet.String(), egressIface, actualName, c.allowPrivate, c.publicIPs)
	if err := fw.apply(); err != nil {
		return fail(fmt.Errorf("iptables setup: %w", err))
	}

	log.Printf("vpn: TUN %s up, server=%s client=%s (subnet %s), forwarding out %s",
		actualName, n.serverIP, n.clientIP, n.subnet, egressIface)
	cleanup = func() {
		fw.remove()
		dev.Close()
	}
	return dev, n, cleanup, nil
}

// detectEgressIface parses `ip route get 8.8.8.8`, e.g.:
//
//	8.8.8.8 via 203.0.113.1 dev eth0 src 203.0.113.5 uid 0
func detectEgressIface() (string, error) {
	out, err := runCmd("ip", "route", "get", "8.8.8.8")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not parse egress interface from: %q", out)
}

// detectIptables picks the iptables backend the host already uses, like
// Kubernetes' iptables-wrapper: the one whose save output has more rules.
// The image has both. Both backends filter at the same time, so an
// ACCEPT in the wrong one doesn't help against docker's DROP policy in
// the other, and DOCKER-USER only exists in docker's backend.
func detectIptables() string {
	legacy, errLegacy := countRules("iptables-legacy-save")
	nft, errNft := countRules("iptables-nft-save")
	switch {
	case errLegacy != nil && errNft != nil:
		log.Printf("vpn: could not detect the iptables backend (%v; %v), falling back to plain iptables", errLegacy, errNft)
		return "iptables"
	case errNft != nil:
		return "iptables-legacy"
	case errLegacy != nil:
		return "iptables-nft"
	case legacy > nft:
		return "iptables-legacy"
	}
	return "iptables-nft"
}

// countRules counts rule lines ("-A ...") in the output of an
// iptables-*-save command.
func countRules(saveCmd string) (int, error) {
	out, err := runCmd(saveCmd)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "-") {
			n++
		}
	}
	return n, nil
}

// fwRule is one iptables rule of the vpn channel.
type fwRule struct {
	table string // "" = filter
	chain string
	spec  []string // matches and target
	// insert on top of the chain instead of appending
	insert bool
	// failing to add it is only a warning (nothing security related)
	optional bool
}

// args builds the iptables arguments for op (-C, -A, -I or -D).
func (r fwRule) args(op string) []string {
	var a []string
	if r.table != "" {
		a = append(a, "-t", r.table)
	}
	a = append(a, op, r.chain)
	if op == "-I" {
		a = append(a, "1")
	}
	return append(a, r.spec...)
}

// firewall is the iptables setup of the vpn channel.
type firewall struct {
	bin string
	// in the order they end up in each chain, top to bottom
	rules []fwRule
	// rules of older versions or settings, deleted before adding ours
	stale []fwRule
}

func (f *firewall) run(args ...string) error {
	// -w: wait for the xtables lock, docker may be changing rules too
	_, err := runCmd(f.bin, append([]string{"-w", "10"}, args...)...)
	return err
}

// newVPNFirewall builds the rule list. tunIface is the vpn TUN.
func newVPNFirewall(bin, subnet, egressIface, tunIface string, allowPrivate bool, publicIPs []net.IP) *firewall {
	f := &firewall{bin: bin}
	f.rules = append(f.rules,
		// without NAT nothing works
		fwRule{table: "nat", chain: "POSTROUTING", spec: []string{"-s", subnet, "-o", egressIface, "-j", "MASQUERADE"}},
		// vpn clients must not reach services of the VPS itself (sshd,
		// Xray, docker) through the tunnel; the tunnel only forwards
		fwRule{chain: "INPUT", spec: []string{"-i", tunIface, "-j", "DROP"}, insert: true},
	)

	// docker sets the FORWARD policy to DROP and checks DOCKER-USER
	// first, so with docker the same rules have to be there too
	chains := []string{"FORWARD"}
	if f.run("-S", "DOCKER-USER") == nil {
		chains = append(chains, "DOCKER-USER")
	} else {
		log.Printf("vpn: no DOCKER-USER chain (docker is not running on this host), using FORWARD only")
	}

	for _, chain := range chains {
		drop := func(match ...string) fwRule {
			spec := append([]string{"-i", tunIface}, match...)
			return fwRule{chain: chain, spec: append(spec, "-j", "DROP"), insert: true}
		}
		// cloud metadata service (169.254.169.254)
		f.rules = append(f.rules, drop("-d", "169.254.0.0/16"))
		// private networks behind the VPS (cloud VPC, docker networks)
		for _, cidr := range egress.PrivateCIDRs {
			r := drop("-d", cidr)
			if allowPrivate {
				// switched on after an earlier run without it
				f.stale = append(f.stale, r)
			} else {
				f.rules = append(f.rules, r)
			}
		}
		// the public IP in 1:1 NAT clouds is not on an interface, so the
		// INPUT rule above doesn't catch it
		for _, ip := range publicIPs {
			if ip.To4() != nil {
				f.rules = append(f.rules, drop("-d", ip.String()))
			}
		}
		// SMTP spam from the VPS gets it banned by the hoster
		f.rules = append(f.rules, drop("-p", "tcp", "--dport", "25"))
		f.rules = append(f.rules,
			// towards the client only replies to its own connections;
			// anyone routing the vpn subnet via the VPS must not reach it
			fwRule{chain: chain, spec: []string{"-o", tunIface, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}, insert: true},
			fwRule{chain: chain, spec: []string{"-o", tunIface, "-j", "DROP"}, insert: true},
			fwRule{chain: chain, spec: []string{"-i", tunIface, "-j", "ACCEPT"}, insert: true},
		)
		// older versions accepted everything towards the client
		f.stale = append(f.stale, fwRule{chain: chain, spec: []string{"-o", tunIface, "-j", "ACCEPT"}})
	}

	f.rules = append(f.rules, fwRule{
		table:    "mangle",
		chain:    "FORWARD",
		spec:     []string{"-o", tunIface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		optional: true,
	})
	return f
}

// apply adds the missing rules. If a rule can't be added, the ones
// already there are removed again: half of the rules (NAT without the
// DROPs) is worse than none, the vpn channel just doesn't start.
func (f *firewall) apply() error {
	for _, r := range f.stale {
		_ = f.run(r.args("-D")...) // usually not there
	}
	// every insert goes to position 1, so going from the last rule up
	// leaves them in list order
	for i := len(f.rules) - 1; i >= 0; i-- {
		r := f.rules[i]
		if f.run(r.args("-C")...) == nil {
			continue
		}
		op := "-A"
		if r.insert {
			op = "-I"
		}
		if err := f.run(r.args(op)...); err != nil {
			if r.optional {
				log.Printf("vpn: WARNING: %v", err)
				continue
			}
			f.remove()
			return err
		}
	}
	return nil
}

// remove deletes all rules of the list. Missing ones are fine.
func (f *firewall) remove() {
	for _, r := range f.rules {
		_ = f.run(r.args("-D")...)
	}
}
