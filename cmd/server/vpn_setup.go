package main

import (
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

// setupVPNTun creates and configures the server TUN device and the NAT
// rules. Linux only.
func setupVPNTun(name string, mtu int, subnetCIDR, egressIface string, allowPrivate bool) (tun.Device, vpnNet, error) {
	_, ipnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, vpnNet{}, fmt.Errorf("parse -vpn-subnet %q: %w", subnetCIDR, err)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return nil, vpnNet{}, fmt.Errorf("-vpn-subnet %q is not IPv4", subnetCIDR)
	}
	ones, _ := ipnet.Mask.Size()
	n := vpnNet{
		subnet:   ipnet,
		serverIP: net.IPv4(base[0], base[1], base[2], base[3]|1).To4(),
		clientIP: net.IPv4(base[0], base[1], base[2], base[3]|2).To4(),
	}

	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, vpnNet{}, fmt.Errorf("create TUN: %w", err)
	}
	actualName, _ := dev.Name()
	fail := func(err error) (tun.Device, vpnNet, error) {
		dev.Close()
		return nil, vpnNet{}, err
	}

	if err := run("ip", "addr", "add", fmt.Sprintf("%s/%d", n.serverIP, ones), "dev", actualName); err != nil {
		return fail(fmt.Errorf("ip addr add: %w", err))
	}
	if err := run("ip", "link", "set", "dev", actualName, "up"); err != nil {
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

	if egressIface == "" {
		egressIface, err = detectEgressIface()
		if err != nil {
			return fail(fmt.Errorf("auto-detect egress interface failed, pass -egress-iface explicitly: %w", err))
		}
		log.Printf("vpn: auto-detected egress interface: %s", egressIface)
	}

	if err := ensureIptables(subnetCIDR, egressIface, actualName, allowPrivate); err != nil {
		return fail(fmt.Errorf("iptables setup: %w", err))
	}

	log.Printf("vpn: TUN %s up, server=%s client=%s (subnet %s), forwarding out %s",
		actualName, n.serverIP, n.clientIP, subnetCIDR, egressIface)
	return dev, n, nil
}

// detectEgressIface parses `ip route get 8.8.8.8`, e.g.:
//
//	8.8.8.8 via 203.0.113.1 dev eth0 src 203.0.113.5 uid 0
func detectEgressIface() (string, error) {
	out, err := exec.Command("ip", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not parse egress interface from: %q", string(out))
}

// iptablesRule has the args to check a rule (-C) and to add it.
type iptablesRule struct {
	check, add []string
}

// ensureIptables adds NAT, FORWARD and MSS clamp rules if they're not
// there yet.
func ensureIptables(subnetCIDR, egressIface, tunIface string, allowPrivate bool) error {
	// without MASQUERADE nothing works, the other rules are optional
	masquerade := iptablesRule{
		check: []string{"-t", "nat", "-C", "POSTROUTING", "-s", subnetCIDR, "-o", egressIface, "-j", "MASQUERADE"},
		add:   []string{"-t", "nat", "-A", "POSTROUTING", "-s", subnetCIDR, "-o", egressIface, "-j", "MASQUERADE"},
	}
	if err := run("iptables", masquerade.check...); err != nil {
		if err := run("iptables", masquerade.add...); err != nil {
			return fmt.Errorf("iptables %v: %w", masquerade.add, err)
		}
	}

	rules := []iptablesRule{
		// vpn clients must not reach services of the VPS itself (sshd,
		// Xray, docker) through the tunnel; the tunnel only forwards.
		{
			check: []string{"-C", "INPUT", "-i", tunIface, "-j", "DROP"},
			add:   []string{"-I", "INPUT", "1", "-i", tunIface, "-j", "DROP"},
		},
		// ...and not the cloud metadata service (169.254.169.254)
		{
			check: []string{"-C", "FORWARD", "-i", tunIface, "-d", "169.254.0.0/16", "-j", "DROP"},
			add:   []string{"-I", "FORWARD", "1", "-i", tunIface, "-d", "169.254.0.0/16", "-j", "DROP"},
		},
		// docker sets FORWARD policy to DROP, our rules have to go into
		// DOCKER-USER which is checked first
		{
			check: []string{"-C", "DOCKER-USER", "-i", tunIface, "-j", "ACCEPT"},
			add:   []string{"-I", "DOCKER-USER", "1", "-i", tunIface, "-j", "ACCEPT"},
		},
		{
			check: []string{"-C", "DOCKER-USER", "-o", tunIface, "-j", "ACCEPT"},
			add:   []string{"-I", "DOCKER-USER", "1", "-o", tunIface, "-j", "ACCEPT"},
		},
		// DOCKER-USER is checked before FORWARD, so the metadata block
		// has to be there too (inserted after the ACCEPTs = on top)
		{
			check: []string{"-C", "DOCKER-USER", "-i", tunIface, "-d", "169.254.0.0/16", "-j", "DROP"},
			add:   []string{"-I", "DOCKER-USER", "1", "-i", tunIface, "-d", "169.254.0.0/16", "-j", "DROP"},
		},
		// for hosts without docker
		{
			check: []string{"-C", "FORWARD", "-i", tunIface, "-j", "ACCEPT"},
			add:   []string{"-A", "FORWARD", "-i", tunIface, "-j", "ACCEPT"},
		},
		{
			check: []string{"-C", "FORWARD", "-o", tunIface, "-j", "ACCEPT"},
			add:   []string{"-A", "FORWARD", "-o", tunIface, "-j", "ACCEPT"},
		},
		{
			check: []string{"-t", "mangle", "-C", "FORWARD", "-o", tunIface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
			add:   []string{"-t", "mangle", "-A", "FORWARD", "-o", tunIface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		},
	}
	for _, r := range rules {
		if err := run("iptables", r.check...); err == nil {
			continue
		}
		if err := run("iptables", r.add...); err != nil {
			log.Printf("vpn: WARNING: iptables %v failed (%v), traffic on %s may be dropped", r.add, err, tunIface)
		}
	}

	// Private networks behind the VPS (cloud VPC, docker networks) are
	// not reachable from the tunnel unless allow_private_destinations is
	// on. Inserted last = on top of both chains.
	for _, chain := range []string{"FORWARD", "DOCKER-USER"} {
		for _, cidr := range egress.PrivateCIDRs {
			rule := []string{chain, "-i", tunIface, "-d", cidr, "-j", "DROP"}
			exists := run("iptables", append([]string{"-C"}, rule...)...) == nil
			switch {
			case !allowPrivate && !exists:
				if err := run("iptables", append([]string{"-I", chain, "1"}, rule[1:]...)...); err != nil {
					log.Printf("vpn: WARNING: could not block %s in %s: %v", cidr, chain, err)
				}
			case allowPrivate && exists:
				// switched on after an earlier run without it
				_ = run("iptables", append([]string{"-D"}, rule...)...)
			}
		}
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
