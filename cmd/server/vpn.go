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

// currentVPN is the single registered full-tunnel peer. This is a
// personal VPN, not multi-tenant — a new connection simply evicts
// whatever was previously registered, matching how a personal
// WireGuard-style endpoint behaves.
var (
	vpnMu      sync.Mutex
	currentVPN *vpnPeer
	vpnSeq     uint32

	// vpnDownRate is the server->client shaping rate in Mbit/s (0 = off),
	// set once from config at startup.
	vpnDownRate float64
)

// vpnPeer pairs a client connection with the queue feeding it. The TUN
// reader only ever enqueues (never blocks on the network), and one
// writer goroutine drains the queue into the connection — so the order
// packets leave in is decided by sched's fair queueing, not by whatever
// happened to be written first into a socket buffer.
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
			p.conn.Close() // unblocks handleVPNConn's reader, which cleans up
			return
		}
	}
}

// logQueueDrops reports, every 30s and only when something happened,
// how many packets the queue dropped — the visible sign that a bulk
// transfer was outrunning the link and got slowed down instead of
// building a queue everything else would have to wait behind.
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

// setupVPNTun creates the server's own TUN device, addresses it, brings
// it up, enables IPv4 forwarding, and installs idempotent iptables rules
// so packets routed onto that device reach the real internet and back.
// Linux-only — the server always runs on the VPS.
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

	// Docker remounts /proc/sys read-only inside the container by
	// default (independent of capabilities — only --privileged lifts
	// it), and network sysctls aren't settable via `--sysctl` under
	// network_mode: host anyway. So this is a host-level prerequisite,
	// not something the container can fix itself: check it, and fail
	// with an actionable message instead of trying to write it.
	if cur, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf("read ip_forward: %w", err)
	} else if strings.TrimSpace(string(cur)) != "1" {
		dev.Close()
		return nil, nil, nil, "", fmt.Errorf(
			"net.ipv4.ip_forward is not enabled on the host — run this on the VPS host (not in the container) and retry:\n" +
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

// detectEgressIface asks the kernel what interface it would use to reach
// the public internet — the same info `ip route get` reports
// interactively. Typical output:
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

// iptablesRule is one rule expressed as its own check (exit 0 = already
// present) and add invocation, kept as separate literals rather than
// derived from one another so the args stay easy to read and verify.
type iptablesRule struct {
	check, add []string
}

// ensureIptables adds the MASQUERADE + FORWARD + MSS-clamp rules this
// tunnel needs, skipping any that are already present so restarting the
// server never duplicates rules.
func ensureIptables(subnetCIDR, egressIface, tunIface string) error {
	// MASQUERADE is the one rule that's fatal if it can't be applied —
	// without it there's no NAT and the VPN can't work at all. The rest
	// (FORWARD/DOCKER-USER accept rules, MSS clamping) are best-effort:
	// their absence usually just means "the host's default FORWARD
	// policy already accepts everything" or "no Docker-managed chain
	// exists here" — worth a loud warning, not worth crash-looping the
	// entire server (which would also take down the unrelated reliable/
	// droppable/glue channels).
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
		// Docker manages the FORWARD chain itself (DOCKER-USER then
		// DOCKER-FORWARD jumps, ahead of anything we append to FORWARD
		// directly) and typically defaults FORWARD's policy to DROP —
		// an ACCEPT rule appended to FORWARD can be dead code if
		// DOCKER-FORWARD already terminates the packet first. DOCKER-USER
		// is the chain Docker documents specifically for user rules that
		// must run before its own logic, so put the real ACCEPT rules
		// there (inserted at the top, not appended, so nothing already in
		// that chain can shadow them).
		{
			check: []string{"-C", "DOCKER-USER", "-i", tunIface, "-j", "ACCEPT"},
			add:   []string{"-I", "DOCKER-USER", "1", "-i", tunIface, "-j", "ACCEPT"},
		},
		{
			check: []string{"-C", "DOCKER-USER", "-o", tunIface, "-j", "ACCEPT"},
			add:   []string{"-I", "DOCKER-USER", "1", "-o", tunIface, "-j", "ACCEPT"},
		},
		// Belt-and-suspenders for non-Docker hosts (no DOCKER-USER chain,
		// plain FORWARD policy DROP) — harmless no-op where DOCKER-USER
		// already accepted the packet.
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
			continue // already present
		}
		if err := run("iptables", r.add...); err != nil {
			log.Printf("vpn: WARNING: iptables %v failed (%v) — full-tunnel traffic through %s may be dropped by the host's own FORWARD policy; check manually", r.add, err, tunIface)
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

// vpnTunReader is the single reader for the server's TUN device. Every
// packet the kernel routes back onto this interface (real replies from
// the internet, un-MASQUERADE'd back to the tunnel subnet) goes to
// whoever is currently the registered VPN client.
func vpnTunReader(dev tun.Device) {
	// Linux enables GRO/offload on the TUN device whenever the kernel
	// supports it (tun.CreateTUN does this unconditionally — see
	// setupVPNTun), which means a single Read can hand back a
	// GRO-coalesced "superpacket" from a real TCP flow well past the
	// interface MTU — wireguard-go's own internal read buffer reserves
	// a full 65535 bytes for exactly this. Sizing ours at mtu+32 (fine
	// on Windows/wintun, which never coalesces) would make Read fail
	// with "overflows bufs element" on the first sufficiently bulky
	// download/page load, and that error is currently fatal below.
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
			// Marshal copies pkt, so bufs can be reused on the next Read.
			peer.q.Enqueue(sched.FlowOf(pkt), frame.New(nextVPNSeq(), pkt).Marshal())
		}
	}
}

// handleVPNConn is the accept-loop handler for the full-tunnel channel.
// Deliberately no session ID handshake (unlike handleDroppableConn/
// handleGlueConn) — there's exactly one logical VPN peer.
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
			continue // client keepalive, not a packet
		}
		if _, err := dev.Write([][]byte{withVirtioHdr(f.Payload)}, virtioHdrLen); err != nil {
			log.Printf("vpn: TUN write: %v", err)
		}
	}
}

// virtioHdrLen mirrors the size of wireguard-go's internal (unexported)
// virtioNetHdr struct — 6 fields, all uint8/uint16, no padding, 10
// bytes. On Linux, tun.CreateTUN enables IFF_VNET_HDR whenever the
// kernel's TUN driver supports it, and Write then requires this many
// bytes of header room before the packet even when no offload is in use
// (an all-zero header, which is what withVirtioHdr produces, means "no
// offload" — exactly what a plain passthrough packet needs). Harmless
// on the rarer kernel that lacks IFF_VNET_HDR support too: Write treats
// the offset as a plain data-start index in that case, and the packet
// still begins at bufs[0][virtioHdrLen:] either way.
const virtioHdrLen = 10

func withVirtioHdr(payload []byte) []byte {
	buf := make([]byte, virtioHdrLen+len(payload))
	copy(buf[virtioHdrLen:], payload)
	return buf
}
