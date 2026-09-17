package main

import (
	"crypto/rand"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/pktfilter"
	"tcp-dormtun/internal/procmap"
	"tcp-dormtun/internal/transport"
)

// vpnKeepaliveInterval is how often an empty frame goes out when there's
// no real traffic. Some NATs/firewalls (observed on the dorm network
// this project targets) silently drop an idle TCP connection carrying no
// data within a couple of minutes; a small periodic write is enough to
// keep it classified as active.
const vpnKeepaliveInterval = 20 * time.Second

// gameFlowIdleTimeout bounds how long a glue-routed flow's bookkeeping
// entry survives with no traffic — a long session touching many
// ephemeral UDP flows would otherwise leak them for its whole lifetime.
// (Server-side glue session/flow cleanup is a separate, broader gap —
// see IDEAS.md P1 #7 — this only covers the client-side maps this mode
// adds.)
const gameFlowIdleTimeout = 60 * time.Second

// runVPNMode is the full-tunnel counterpart to runTunMode: it forwards
// every non-noise IPv4 packet whole, byte-for-byte, over one vpn TLS
// connection — the server writes each one into its own TUN device and
// lets the kernel do real routing+NAT, so ordinarily there's no flow
// bookkeeping or packet rebuild here at all.
//
// The exception: if gameProcesses is non-empty, UDP packets whose local
// source port is currently owned by one of those processes (resolved
// live via internal/procmap, the Windows IP Helper API) are instead
// routed through gamePaths parallel glue connections with multipath
// duplication — the same droppable/multipath mechanism runTunMode uses,
// which vpn mode's single TCP stream can't offer on its own (a burst of
// small packets on one TCP connection is exactly the head-of-line-
// blocking scenario this project's glue channel exists to avoid). With
// gameProcesses empty, none of this runs and behavior is identical to
// before — zero cost, fully backward compatible.
func runVPNMode(vpnAddr string, insecure bool, pin []byte, tunName string, mtu int, key []byte, glueAddr string, gameProcesses []string, gamePaths int) {
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	defer dev.Close()
	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, tunName, mtu)

	// Shared across the vpn reply reader and any glue reply readers
	// below — wintun's Write (AllocateSendPacket + SendPacket as two
	// separate calls) has no documented guarantee of being safe for
	// concurrent callers, so serialize rather than assume.
	var devMu sync.Mutex
	devWrite := func(pkt []byte) {
		devMu.Lock()
		_, err := dev.Write([][]byte{pkt}, 0)
		devMu.Unlock()
		if err != nil {
			log.Printf("TUN write: %v", err)
		}
	}

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
			devWrite(f.Payload)
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

	// --- optional: selective multipath for matched game processes' UDP ---

	gameTraffic := len(gameProcesses) > 0
	var (
		glueConns     []net.Conn
		procTable     *procmap.Table
		flowsMu       sync.Mutex
		flows         = make(map[uint16]flowInfo)
		flowIDs       = make(map[flowKey]uint16)
		flowIDCounter uint16
		flowLastSeen  = make(map[uint16]time.Time)
		glueSeqMu     sync.Mutex
		glueSeq       uint32
	)
	nextGlueSeq := func() uint32 {
		glueSeqMu.Lock()
		glueSeq++
		v := glueSeq
		glueSeqMu.Unlock()
		return v
	}
	writeAllGluePaths := func(wire []byte) {
		for _, c := range glueConns {
			if _, err := c.Write(wire); err != nil {
				log.Printf("glue write: %v", err)
			}
		}
	}
	isGameProcess := func(name string) bool {
		for _, g := range gameProcesses {
			if g == name {
				return true
			}
		}
		return false
	}

	if gameTraffic {
		sid := make([]byte, 8)
		if _, err := rand.Read(sid); err != nil {
			log.Fatalf("generate glue session id: %v", err)
		}
		for i := 0; i < gamePaths; i++ {
			c, err := transport.Dial(glueAddr, insecure, pin)
			if err != nil {
				log.Fatalf("dial glue path %d: %v", i, err)
			}
			if key != nil {
				if err := auth.ClientHandshake(c, key); err != nil {
					log.Fatalf("auth on glue path %d: %v", i, err)
				}
			}
			if _, err := c.Write(sid); err != nil {
				log.Fatalf("send glue session id on path %d: %v", i, err)
			}
			glueConns = append(glueConns, c)
		}
		defer func() {
			for _, c := range glueConns {
				c.Close()
			}
		}()
		log.Printf("connected to glue channel %s over %d path(s) for: %s", glueAddr, gamePaths, strings.Join(gameProcesses, ", "))

		// Replies come back duplicated across every glue path, so a
		// receiver dedupes them here before reinjecting — same pattern
		// runTunMode uses for its own glue reply path.
		replyRecv := frame.NewReceiver(150 * time.Millisecond)
		var replyMu sync.Mutex
		for _, c := range glueConns {
			go func(c net.Conn) {
				for {
					f, err := frame.ReadFrame(c)
					if err != nil {
						log.Printf("glue: path closed: %v", err)
						return
					}
					// Measurement/keepalive ping echo — bypasses the TTL/dedup
					// receiver entirely (see internal/frame's AcceptSeq), same
					// as runTunMode: a late reply is exactly what a real
					// measurement would want to see, not something to drop.
					if _, isPing := glue.DecodePing(f.Payload); isPing {
						continue
					}

					replyMu.Lock()
					ok, _ := replyRecv.Accept(f)
					replyMu.Unlock()
					if !ok {
						continue // duplicate copy from another path
					}

					flowID, payload, err := glue.DecodeInbound(f.Payload)
					if err != nil {
						continue
					}
					flowsMu.Lock()
					fi, known := flows[flowID]
					flowsMu.Unlock()
					if !known {
						continue
					}
					devWrite(pktfilter.BuildIPv4UDP(fi.origDst, fi.origSrc, fi.origDstPort, fi.origSrcPort, payload))
				}
			}(c)
		}

		// Keepalive on the glue paths too — the same idle-connection
		// timeout risk already guarded against on the vpn connection
		// above applies here between game-action bursts.
		go func() {
			ticker := time.NewTicker(vpnKeepaliveInterval)
			defer ticker.Stop()
			for range ticker.C {
				writeAllGluePaths(frame.New(nextGlueSeq(), glue.EncodePing(0)).Marshal())
			}
		}()

		procTable = procmap.New()
		if err := procTable.Refresh(); err != nil {
			log.Printf("procmap: initial refresh: %v", err)
		}
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				if err := procTable.Refresh(); err != nil {
					log.Printf("procmap: refresh: %v", err)
				}

				flowsMu.Lock()
				now := time.Now()
				for id, last := range flowLastSeen {
					if now.Sub(last) <= gameFlowIdleTimeout {
						continue
					}
					delete(flowLastSeen, id)
					delete(flows, id)
					for k, v := range flowIDs {
						if v == id {
							delete(flowIDs, k)
							break
						}
					}
				}
				flowsMu.Unlock()
			}
		}()
	}

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

			if gameTraffic && info.Proto == 17 {
				if procName, found := procTable.ProcessForUDPPort(info.SrcPort); found && isGameProcess(procName) {
					var fi flowInfo
					copy(fi.origSrc[:], info.Src.To4())
					copy(fi.origDst[:], info.Dst.To4())
					fi.origSrcPort = info.SrcPort
					fi.origDstPort = info.DstPort

					fkey := flowKey{srcPort: info.SrcPort, dst: fi.origDst, dstPort: info.DstPort}

					flowsMu.Lock()
					flowID := allocFlowID(flowIDs, &flowIDCounter, fkey)
					flows[flowID] = fi
					flowLastSeen[flowID] = time.Now()
					flowsMu.Unlock()

					envelope := glue.EncodeOutbound(flowID, info.Dst, info.DstPort, info.Payload)
					writeAllGluePaths(frame.New(nextGlueSeq(), envelope).Marshal())
					continue
				}
			}

			if err := writeFrame(bufs[i][:sizes[i]]); err != nil {
				log.Printf("vpn write: %v", err)
			}
		}
	}
}
