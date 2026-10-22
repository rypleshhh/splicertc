package main

import (
	"fmt"
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

// On an unknown UDP port the port table is reloaded in the background,
// but not more often than this.
const procRefreshOnMiss = 100 * time.Millisecond

// The vpn writer sends up to this many bytes of queued frames with one
// write: one TLS record and one syscall instead of one per packet.
const vpnBatchBytes = 16 * 1024

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
// reconnect by themselves. It returns an error if the first connect
// fails, on a permanent error (wrong key or certificate) and if the TUN
// device fails; the TUN device and the vpn connection are closed first.
func runVPNMode(srv endpoint, key []byte, tunName string, mtu int, glueSrv endpoint, gameProcesses []string, gamePaths int, upMbps float64) error {
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer dev.Close()
	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, tunName, mtu)

	// the first error that has to stop the client; goroutines report
	// here instead of exiting, so the deferred cleanup runs
	stop := make(chan error, 1)
	fail := func(err error) {
		select {
		case stop <- err:
		default:
		}
	}

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
		addr:        srv.addr,
		dial:        func() (net.Conn, error) { return dialVPN(srv, key) },
		onPacket:    devWrite,
		readTimeout: vpnReadTimeout,
	}
	conn, err := link.dial()
	if err != nil {
		return fmt.Errorf("dial vpn channel: %w", err)
	}
	defer link.close()
	// the tray looks for this line and routes this IP around the tunnel
	log.Printf("connected to vpn channel %s", srv.addr)
	go func() {
		if err := link.run(conn); err != nil {
			fail(err)
		}
	}()

	var seq atomic.Uint32
	vq := sched.New(sched.Config{})
	defer vq.Close()
	if upMbps > 0 {
		log.Printf("vpn: shaping client->server to %.1f Mbit/s", upMbps)
	}
	go func() {
		shaper := sched.NewShaper(upMbps)
		var batch [][]byte
		var buf []byte
		for {
			var ok bool
			batch, ok = vq.DequeueBatch(batch, vpnBatchBytes)
			if !ok {
				return
			}
			buf = buf[:0]
			for _, wire := range batch {
				buf = append(buf, wire...)
			}
			clear(batch) // don't keep the frames alive until the next batch
			shaper.Wait(len(buf))
			link.write(buf)
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

	var (
		split   *gameSplit
		paths   *gluePaths
		glueSeq atomic.Uint32
	)
	if len(gameProcesses) > 0 {
		flows := newFlowTable()
		paths, err = startGluePaths(glueSrv, key, gamePaths, glueReplyHandler(flows, devWrite, nil), fail)
		if err != nil {
			return fmt.Errorf("dial glue channel: %w", err)
		}
		log.Printf("connected to glue channel %s over %d path(s) for: %s", glueSrv.addr, paths.live(), strings.Join(gameProcesses, ", "))

		procTable := procmap.New()
		if err := procTable.Refresh(); err != nil {
			log.Printf("procmap: initial refresh: %v", err)
		}
		// the Windows API call takes ~0.2-0.3 ms, too long for the TUN
		// read loop, so a miss only asks for a refresh in the background
		onMiss := startRefresher(func() {
			if err := procTable.Refresh(); err != nil {
				log.Printf("procmap: refresh: %v", err)
			}
		}, procRefreshOnMiss)
		router := newUDPRouter(
			procTable.ProcessForUDPPort,
			onMiss.kick,
			func(name string) bool {
				for _, g := range gameProcesses {
					if g == name {
						return true
					}
				}
				return false
			},
		)
		split = &gameSplit{router: router, flows: flows}

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

	go func() {
		batch := dev.BatchSize()
		bufs := make([][]byte, batch)
		for i := range bufs {
			bufs[i] = make([]byte, mtu+32)
		}
		sizes := make([]int, batch)
		fragDrops := dropCounter{what: "UDP fragments to game servers (glue can't carry fragments)", every: time.Minute}

		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				fail(fmt.Errorf("TUN read: %w", err))
				return
			}
			now := time.Now()
			for i := 0; i < n; i++ {
				pkt := bufs[i][:sizes[i]]
				info, ok := pktfilter.Parse(pkt)
				if !ok || info.Noise || info.Version != 4 {
					continue // noise or IPv6
				}

				if split != nil {
					action, flowID := split.decide(info, now)
					switch action {
					case dropUnknown:
						continue
					case dropFragment:
						fragDrops.add(now)
						continue
					case toGlue:
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
	}()

	return <-stop
}

// dropCounter counts dropped packets and logs the total at most once per
// interval, not for every packet. Not safe for concurrent use.
type dropCounter struct {
	what    string
	every   time.Duration
	n       uint64
	lastLog time.Time
}

func (d *dropCounter) add(now time.Time) {
	d.n++
	if d.lastLog.IsZero() || now.Sub(d.lastLog) >= d.every {
		log.Printf("vpn: dropped %d %s so far", d.n, d.what)
		d.lastLog = now
	}
}
