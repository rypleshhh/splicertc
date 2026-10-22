package main

import (
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/pktfilter"
	"tcp-dormtun/internal/procmap"
	"tcp-dormtun/internal/sched"
)

// Game flows with no traffic for this long are removed.
const gameFlowIdleTimeout = 60 * time.Second

// On an unknown UDP port the port table is reloaded, but not more often
// than this.
const procRefreshOnMiss = 100 * time.Millisecond

// keepalives get their own flow so they're not stuck behind a download
var keepaliveFlow = sched.FlowKey{Proto: 255}

// runVPNMode sends all IPv4 packets from the TUN device to the server,
// which puts them into its own TUN and does NAT.
//
// If gameProcesses is set, UDP from those processes goes through the
// glue channel instead (several parallel connections with duplication),
// to avoid head-of-line blocking on the single vpn connection.
//
// The TUN read loop never blocks on the network: vpn packets go to the
// scheduler, game packets go to the path writers. Both channels
// reconnect by themselves, only the first connect failing is fatal.
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

	link := &vpnLink{
		addr:        vpnAddr,
		dial:        func() (net.Conn, error) { return dialVPN(vpnAddr, insecure, pin, key) },
		onPacket:    devWrite,
		readTimeout: vpnReadTimeout,
	}
	conn, err := link.dial()
	if err != nil {
		log.Fatalf("dial vpn channel: %v", err)
	}
	log.Printf("connected to vpn channel %s", vpnAddr)
	go link.run(conn)

	var seq atomic.Uint32
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
			link.write(wire)
		}
	}()

	go func() {
		ticker := time.NewTicker(vpnKeepaliveInterval)
		defer ticker.Stop()
		for range ticker.C {
			vq.Enqueue(keepaliveFlow, frame.New(seq.Add(1), nil).Marshal())
		}
	}()

	// game traffic over glue (only if game_processes is set)

	gameTraffic := len(gameProcesses) > 0
	var (
		paths   *gluePaths
		router  *udpRouter
		flows   = newFlowTable()
		glueSeq atomic.Uint32
	)

	if gameTraffic {
		paths, err = startGluePaths(glueAddr, insecure, pin, key, gamePaths, glueReplyHandler(flows, devWrite, nil))
		if err != nil {
			log.Fatalf("dial glue channel: %v", err)
		}
		log.Printf("connected to glue channel %s over %d path(s) for: %s", glueAddr, paths.live(), strings.Join(gameProcesses, ", "))

		procTable := procmap.New()
		if err := procTable.Refresh(); err != nil {
			log.Printf("procmap: initial refresh: %v", err)
		}
		router = newUDPRouter(
			procTable.ProcessForUDPPort,
			func() {
				if _, err := procTable.RefreshIfOlder(procRefreshOnMiss); err != nil {
					log.Printf("procmap: refresh: %v", err)
				}
			},
			func(name string) bool {
				for _, g := range gameProcesses {
					if g == name {
						return true
					}
				}
				return false
			},
		)

		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for now := range ticker.C {
				if err := procTable.Refresh(); err != nil {
					log.Printf("procmap: refresh: %v", err)
				}
				router.sweep(now, gameFlowIdleTimeout)
				flows.sweep(now, gameFlowIdleTimeout)
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
		now := time.Now()
		for i := 0; i < n; i++ {
			pkt := bufs[i][:sizes[i]]
			info, ok := pktfilter.Parse(pkt)
			if !ok || info.Noise || info.Version != 4 {
				continue // noise or IPv6
			}

			if gameTraffic && info.Proto == 17 && info.Payload != nil {
				fi := flowInfo{origSrcPort: info.SrcPort, origDstPort: info.DstPort}
				copy(fi.origSrc[:], info.Src.To4())
				copy(fi.origDst[:], info.Dst.To4())

				useGlue, send := router.classify(flowKeyOf(fi), now)
				if !send {
					continue // owner not known yet
				}
				if useGlue {
					flowID, ok := flows.id(fi, now)
					if !ok {
						continue // all flow IDs in use
					}
					envelope, err := glue.EncodeOutbound(flowID, info.Dst, info.DstPort, info.Payload)
					if err != nil {
						continue // only IPv4 gets here
					}
					paths.send(frame.New(glueSeq.Add(1), envelope).Marshal())
					continue
				}
			}

			// Marshal copies pkt
			vq.Enqueue(sched.FlowOf(pkt), frame.New(seq.Add(1), pkt).Marshal())
		}
	}
}
