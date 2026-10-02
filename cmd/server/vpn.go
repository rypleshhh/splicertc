package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/sched"
)

// Only one vpn client at a time, a new one replaces the old one.
var (
	vpnMu      sync.Mutex
	currentVPN *vpnPeer
	vpnSeq     uint32

	// Mbit/s, 0 = no limit
	vpnDownRate float64
)

// vpnPeer is a client connection plus its send queue. The TUN reader
// only puts packets in the queue, writeLoop sends them.
type vpnPeer struct {
	conn net.Conn
	q    *sched.Scheduler
}

func (p *vpnPeer) writeLoop() {
	shaper := sched.NewShaper(vpnDownRate)
	for {
		wire, ok := p.q.Dequeue()
		if !ok {
			return
		}
		shaper.Wait(len(wire))
		if _, err := p.conn.Write(wire); err != nil {
			log.Printf("vpn: write to client failed: %v", err)
			p.conn.Close() // handleVPNConn will clean up
			return
		}
	}
}

// logQueueDrops logs queue drops every 30s (if there were any).
func logQueueDrops(name string, q *sched.Scheduler, done <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	var last sched.Stats
	for {
		select {
		case <-done:
			return
		case <-t.C:
			st := q.Stats()
			codel, overflow := st.CodelDrops-last.CodelDrops, st.OverflowDrops-last.OverflowDrops
			if codel+overflow > 0 {
				log.Printf("%s: queue dropped %d packets in 30s (CoDel %d, overflow %d), %d KB queued across %d flows",
					name, codel+overflow, codel, overflow, st.QueuedBytes/1024, st.ActiveFlows)
			}
			last = st
		}
	}
}

func nextVPNSeq() uint32 {
	vpnMu.Lock()
	vpnSeq++
	v := vpnSeq
	vpnMu.Unlock()
	return v
}

// setupVPNTun creates and configures the server TUN device and the NAT
// rules. Linux only.
func setupVPNTun(name string, mtu int, subnetCIDR, egressIface string) (dev tun.Device, serverIP, clientIP net.IP, actualName string, err error) {
	dev, err = tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("create TUN: %w", err)
	}
	actualName, _ = dev.Name()

	ip, ipnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf("parse -vpn-subnet %q: %w", subnetCIDR, err)
	}
	ones, _ := ipnet.Mask.Size()
	base := ip.To4()
	if base == nil {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf("-vpn-subnet %q is not IPv4", subnetCIDR)
	}
	serverIP = net.IPv4(base[0], base[1], base[2], base[3]|1)
	clientIP = net.IPv4(base[0], base[1], base[2], base[3]|2)

	if err := run("ip", "addr", "add", fmt.Sprintf("%s/%d", serverIP, ones), "dev", actualName); err != nil {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf("ip addr add: %w", err)
	}
	if err := run("ip", "link", "set", "dev", actualName, "up"); err != nil {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf("ip link set up: %w", err)
	}

	// can't set this from inside docker, /proc/sys is read-only there
	if cur, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf("read ip_forward: %w", err)
	} else if strings.TrimSpace(string(cur)) != "1" {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf(
			"net.ipv4.ip_forward is off, run on the host (not in docker):\n" +
				"  sudo sysctl -w net.ipv4.ip_forward=1\n" +
				"  echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-dormtun.conf")
	}

	if egressIface == "" {
		egressIface, err = detectEgressIface()
		if err != nil {
			dev.Close()
			return nil, nil, nil, "", fmt.Errorf("auto-detect egress interface failed, pass -egress-iface explicitly: %w", err)
		}
		log.Printf("vpn: auto-detected egress interface: %s", egressIface)
	}

	if err := ensureIptables(subnetCIDR, egressIface, actualName); err != nil {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf("iptables setup: %w", err)
	}

	log.Printf("vpn: TUN %s up, server=%s client=%s (subnet %s), forwarding out %s",
		actualName, serverIP, clientIP, subnetCIDR, egressIface)
	return dev, serverIP, clientIP, actualName, nil
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
func ensureIptables(subnetCIDR, egressIface, tunIface string) error {
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
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// vpnTunReader reads replies from the TUN device and queues them for the
// current client.
func vpnTunReader(dev tun.Device) {
	// with GRO a read can be bigger than MTU
	const maxReadSize = 65535 + 64
	batch := dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, maxReadSize)
	}
	sizes := make([]int, batch)
	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			log.Fatalf("vpn TUN read: %v", err)
		}
		vpnMu.Lock()
		peer := currentVPN
		vpnMu.Unlock()
		if peer == nil {
			continue
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][:sizes[i]]
			// Marshal copies pkt
			peer.q.Enqueue(sched.FlowOf(pkt), frame.New(nextVPNSeq(), pkt).Marshal())
		}
	}
}

// handleVPNConn handles one vpn client connection.
func handleVPNConn(conn net.Conn, dev tun.Device) {
	defer conn.Close()
	name, ok := checkAuth(conn)
	if !ok {
		return
	}

	peer := &vpnPeer{conn: conn, q: sched.New(sched.Config{})}
	done := make(chan struct{})
	go peer.writeLoop()
	go logQueueDrops("vpn", peer.q, done)

	vpnMu.Lock()
	old := currentVPN
	currentVPN = peer
	vpnMu.Unlock()
	if old != nil {
		log.Printf("vpn: new client %s replacing previous peer %s", conn.RemoteAddr(), old.conn.RemoteAddr())
		old.conn.Close()
	}
	log.Printf("vpn: client connected: %s (%q)", conn.RemoteAddr(), name)

	defer func() {
		vpnMu.Lock()
		if currentVPN == peer {
			currentVPN = nil
		}
		vpnMu.Unlock()
		peer.q.Close()
		close(done)
		log.Printf("vpn: client disconnected: %s", conn.RemoteAddr())
	}()

	for {
		f, err := frame.ReadFrame(conn)
		if err != nil {
			return
		}
		if len(f.Payload) == 0 {
			continue // keepalive
		}
		if _, err := dev.Write([][]byte{withVirtioHdr(f.Payload)}, virtioHdrLen); err != nil {
			log.Printf("vpn: TUN write: %v", err)
		}
	}
}

// On Linux wireguard-go's TUN wants a 10 byte virtio header before the
// packet. All zeros = no offload.
const virtioHdrLen = 10

func withVirtioHdr(payload []byte) []byte {
	buf := make([]byte, virtioHdrLen+len(payload))
	copy(buf[virtioHdrLen:], payload)
	return buf
}
