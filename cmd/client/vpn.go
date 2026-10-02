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
	"tcp-dormtun/internal/sched"
	"tcp-dormtun/internal/transport"
)

// The dorm network kills idle TCP connections after a few minutes, so we
// send an empty frame from time to time.
const vpnKeepaliveInterval = 20 * time.Second

// Game flows with no traffic for this long are removed.
// TODO: server side doesn't clean up flows yet.
const gameFlowIdleTimeout = 60 * time.Second

// keepalives get their own flow so they're not stuck behind a download
var keepaliveFlow = sched.FlowKey{Proto: 255}

// Queue size per glue path (~0.5s of game traffic). Older frames would
// be dropped by the server anyway (150ms TTL).
const (
	gluePathDepth  = 32
	glueStaleAfter = 150 * time.Millisecond
)

// runVPNMode sends all IPv4 packets from the TUN device to the server,
// which puts them into its own TUN and does NAT.
//
// If gameProcesses is set, UDP from those processes goes through the
// glue channel instead (several parallel connections with duplication),
// to avoid head-of-line blocking on the single vpn connection.
//
// The TUN read loop never blocks on the network: vpn packets go to the
// scheduler, game packets go to the path writers.
func runVPNMode(vpnAddr string, insecure bool, pin []byte, tunName string, mtu int, key []byte, glueAddr string, gameProcesses []string, gamePaths int, upMbps float64) {
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	defer dev.Close()
	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, tunName, mtu)

	// not sure wintun's Write is safe for concurrent use, so lock it
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
				continue // keepalive
			}
			devWrite(f.Payload)
		}
	}()

	vq := sched.New(sched.Config{})
	defer vq.Close()
	if upMbps > 0 {
		log.Printf("vpn: shaping client->server to %.1f Mbit/s", upMbps)
	}
	go func() {
		shaper := sched.NewShaper(upMbps)
		for {
			wire, ok := vq.Dequeue()
			if !ok {
				return
			}
			shaper.Wait(len(wire))
			if _, err := conn.Write(wire); err != nil {
				log.Printf("vpn write: %v", err)
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(vpnKeepaliveInterval)
		defer ticker.Stop()
		for range ticker.C {
			vq.Enqueue(keepaliveFlow, frame.New(nextSeq(), nil).Marshal())
		}
	}()

	// game traffic over glue (only if game_processes is set)

	gameTraffic := len(gameProcesses) > 0
	var (
		glueConns     []net.Conn
		glueWriters   []*sched.PathWriter
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
	// each path has its own writer so a slow path doesn't block the others
	writeAllGluePaths := func(wire []byte) {
		for _, w := range glueWriters {
			w.Send(wire)
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
			glueWriters = append(glueWriters, sched.NewPathWriter(c, gluePathDepth, glueStaleAfter))
		}
		defer func() {
			for _, w := range glueWriters {
				w.Close()
			}
		}()
		log.Printf("connected to glue channel %s over %d path(s) for: %s", glueAddr, gamePaths, strings.Join(gameProcesses, ", "))

		// replies come on every path, drop the duplicates
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
					// ping reply
					if _, isPing := glue.DecodePing(f.Payload); isPing {
						continue
					}

					replyMu.Lock()
					ok, _ := replyRecv.Accept(f)
					replyMu.Unlock()
					if !ok {
						continue // duplicate
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

		// keepalive for glue paths too
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

	log.Println("waiting for packets, set up the interface and default route")

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
				continue // noise or IPv6
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

			pkt := bufs[i][:sizes[i]]
			// Marshal copies pkt
			vq.Enqueue(sched.FlowOf(pkt), frame.New(nextSeq(), pkt).Marshal())
		}
	}
}
