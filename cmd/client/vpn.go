package main

import (
	"log"
	"sync"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/pktfilter"
	"tcp-dormtun/internal/transport"
)

// runVPNMode is the full-tunnel counterpart to runTunMode: instead of
// parsing UDP and re-encoding a flow-keyed glue envelope, it forwards
// every non-noise IPv4 packet whole, byte-for-byte. The server writes
// each one into its own TUN device and lets the kernel do real
// routing+NAT, so there's no flow bookkeeping or packet rebuild here —
// unlike glue's BuildIPv4UDP, replies from the server are already
// complete, correctly-addressed IP packets.
func runVPNMode(vpnAddr string, insecure bool, tunName string, mtu int, key []byte) {
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	defer dev.Close()
	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, tunName, mtu)

	conn, err := transport.Dial(vpnAddr, insecure)
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
			if _, err := dev.Write([][]byte{f.Payload}, 0); err != nil {
				log.Printf("TUN write: %v", err)
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
			wire := frame.New(nextSeq(), bufs[i][:sizes[i]]).Marshal()
			if _, err := conn.Write(wire); err != nil {
				log.Printf("vpn write: %v", err)
			}
		}
	}
}
