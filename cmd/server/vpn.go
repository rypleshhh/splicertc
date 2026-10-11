package main

import (
	"bytes"
	"log"
	"net"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/sched"
)

// vpn channel: every frame is one whole IPv4 packet. Packets from the
// client go into the server TUN (and out to the internet through NAT),
// packets coming back from the TUN go to the client.
//
// The TUN has one client address (.2), so only one vpn client at a time.
// A new connection from the same client (a reconnect) replaces the old
// one; a different client is refused while the current one is connected.

var (
	vpnMu      sync.Mutex
	currentVPN *vpnPeer
	vpnSeq     uint32

	// Mbit/s, 0 = no limit
	vpnDownRate float64
)

// The client sends a keepalive every 2s. Nothing for vpnReadTimeout
// or a write stuck for vpnWriteTimeout = the connection is dead.
const (
	vpnReadTimeout  = 30 * time.Second
	vpnWriteTimeout = 10 * time.Second
)

// keepalives get their own flow so they're not stuck behind a download
var keepaliveFlow = sched.FlowKey{Proto: 255}

// vpnPeer is a client connection plus its send queue. The TUN reader
// only puts packets in the queue, writeLoop sends them.
type vpnPeer struct {
	name string
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
		_ = p.conn.SetWriteDeadline(time.Now().Add(vpnWriteTimeout))
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
			if len(pkt) > frame.MaxPayload {
				continue // doesn't fit in a frame
			}
			// Marshal copies pkt
			peer.q.Enqueue(sched.FlowOf(pkt), frame.New(nextVPNSeq(), pkt).Marshal())
		}
	}
}

// claimVPN makes peer the current client. A reconnect of the same client
// replaces its old connection, another client gets ok=false.
func claimVPN(peer *vpnPeer) (old *vpnPeer, ok bool) {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	old = currentVPN
	if old != nil && old.name != peer.name {
		return old, false
	}
	currentVPN = peer
	return old, true
}

// handleVPNConn handles one vpn client connection.
func handleVPNConn(conn net.Conn, dev tun.Device, vn vpnNet) {
	defer conn.Close()
	startHandshake(conn)
	name, ok := checkAuth(conn)
	if !ok {
		return
	}
	endHandshake(conn)

	peer := &vpnPeer{name: name, conn: conn, q: sched.New(sched.Config{})}
	old, ok := claimVPN(peer)
	if !ok {
		log.Printf("vpn: refusing %s (%q): vpn channel is used by %q", conn.RemoteAddr(), name, old.name)
		return
	}
	if old != nil {
		log.Printf("vpn: %q reconnected from %s, closing the old connection %s", name, conn.RemoteAddr(), old.conn.RemoteAddr())
		old.conn.Close()
	}
	log.Printf("vpn: client connected: %s (%q)", conn.RemoteAddr(), name)

	done := make(chan struct{})
	go peer.writeLoop()
	go logQueueDrops("vpn", peer.q, done)

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

	spoofLogged := false
	for {
		_ = conn.SetReadDeadline(time.Now().Add(vpnReadTimeout))
		f, err := frame.ReadFrame(conn)
		if err != nil {
			return
		}
		if len(f.Payload) == 0 {
			// keepalive, send it back so the client knows the link works
			peer.q.Enqueue(keepaliveFlow, frame.New(nextVPNSeq(), nil).Marshal())
			continue
		}
		// Only IPv4 from the client's own tunnel address goes out. Without
		// this a client could send packets with someone else's source IP
		// out of the VPS (spoofing for reflection attacks).
		if !fromClient(f.Payload, vn.clientIP) {
			if !spoofLogged {
				spoofLogged = true
				log.Printf("vpn: dropping packets from %q with a source address other than %s", name, vn.clientIP)
			}
			continue
		}
		if _, err := dev.Write([][]byte{withVirtioHdr(f.Payload)}, virtioHdrLen); err != nil {
			log.Printf("vpn: TUN write: %v", err)
		}
	}
}

// fromClient reports if pkt is IPv4 with source address clientIP.
func fromClient(pkt []byte, clientIP net.IP) bool {
	return len(pkt) >= 20 && pkt[0]>>4 == 4 && bytes.Equal(pkt[12:16], clientIP.To4())
}

// On Linux wireguard-go's TUN wants a 10 byte virtio header before the
// packet. All zeros = no offload.
const virtioHdrLen = 10

func withVirtioHdr(payload []byte) []byte {
	buf := make([]byte, virtioHdrLen+len(payload))
	copy(buf[virtioHdrLen:], payload)
	return buf
}
