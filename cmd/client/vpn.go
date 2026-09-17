package main

import (
	"log"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/pktfilter"
	"tcp-dormtun/internal/transport"
)

// vpnKeepaliveInterval is how often an empty frame goes out when there's
// no real traffic. Some NATs/firewalls (observed on the dorm network
// this project targets) silently drop an idle TCP connection carrying no
// data within a couple of minutes; a small periodic write is enough to
// keep it classified as active.
const vpnKeepaliveInterval = 20 * time.Second

// runVPNMode is the full-tunnel counterpart to runTunMode: instead of
// parsing UDP and re-encoding a flow-keyed glue envelope, it forwards
// every non-noise IPv4 packet whole, byte-for-byte. The server writes
// each one into its own TUN device and lets the kernel do real
// routing+NAT, so there's no flow bookkeeping or packet rebuild here —
// unlike glue's BuildIPv4UDP, replies from the server are already
// complete, correctly-addressed IP packets.
func runVPNMode(vpnAddr string, insecure bool, pin []byte, tunName string, mtu int, key []byte) {
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	defer dev.Close()
	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, tunName, mtu)

	conn, err := transport.Dial(vpnAddr, insecure, pin)
	if err != nil {
		log.Fatalf("dial vpn channel: %v", err)
	}
	defer conn.Close()
	if key != nil {
		if err := auth.ClientHandshake(conn, key); err != nil {
			log.Fatalf("auth: %v", err)
		}
	}
	log.Printf("connected to vpn channel %s", vpnAddr)

	var seqMu sync.Mutex
	var seq uint32
	nextSeq := func() uint32 {
		seqMu.Lock()
		seq++
		v := seq
		seqMu.Unlock()
		return v
	}

	go func() {
		for {
			f, err := frame.ReadFrame(conn)
			if err != nil {
				log.Fatalf("vpn: connection closed: %v", err)
			}
			if len(f.Payload) == 0 {
				continue // peer keepalive, not a packet
			}
			if _, err := dev.Write([][]byte{f.Payload}, 0); err != nil {
				log.Printf("TUN write: %v", err)
			}
		}
	}()

	var writeMu sync.Mutex
	writeFrame := func(payload []byte) error {
		wire := frame.New(nextSeq(), payload).Marshal()
		writeMu.Lock()
		_, err := conn.Write(wire)
		writeMu.Unlock()
		return err
	}

	go func() {
		ticker := time.NewTicker(vpnKeepaliveInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := writeFrame(nil); err != nil {
				log.Printf("vpn: keepalive write: %v", err)
			}
		}
	}()

	log.Println("waiting for outbound traffic to tunnel — bring the interface up and set it as the default route")

	batch := dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+32)
	}
	sizes := make([]int, batch)

	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			log.Fatalf("TUN read: %v", err)
		}
		for i := 0; i < n; i++ {
			info, ok := pktfilter.Parse(bufs[i][:sizes[i]])
			if !ok || info.Noise || info.Version != 4 {
				continue // local discovery noise, or IPv6 (not forwarded in Phase 1)
			}
			if err := writeFrame(bufs[i][:sizes[i]]); err != nil {
				log.Printf("vpn write: %v", err)
			}
		}
	}
}
