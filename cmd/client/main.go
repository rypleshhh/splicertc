package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/measure"
	"tcp-dormtun/internal/pktfilter"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/socks5"
	"tcp-dormtun/internal/transport"
)

func main() {
	mode := flag.String("mode", "socks5", "socks5 (default), droptest, or tun")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	serverAddr := flag.String("server", "127.0.0.1:8443", "tunnel server address")
	dropAddr := flag.String("drop-addr", "127.0.0.1:8444", "droppable channel address (droptest mode)")
	glueAddr := flag.String("glue-addr", "127.0.0.1:8446", "glue channel address (tun mode)")
	tunName := flag.String("tun-name", "dormtun0", "TUN interface name (tun mode)")
	tunMTU := flag.Int("tun-mtu", 1420, "TUN interface MTU (tun mode)")
	tunPaths := flag.Int("tun-paths", 1, "tun mode: number of parallel duplicated paths (1 = no duplication)")
	tunMeasure := flag.Bool("tun-measure", false, "tun mode: send measurement pings and print RTT/jitter/loss periodically")
	tunMeasureInterval := flag.Duration("tun-measure-interval", 33*time.Millisecond, "tun mode: spacing between measurement pings")
	dropCount := flag.Int("drop-count", 0, "droptest: if >0, send this many frames at -drop-interval spacing instead of the fixed delay demo")
	dropInterval := flag.Duration("drop-interval", 33*time.Millisecond, "droptest: spacing between frames in stress mode (33ms ~ 30 ticks/sec, like a game sending state updates)")
	dropPaths := flag.Int("drop-paths", 1, "droptest stress mode: number of parallel TLS connections to duplicate each frame across")
	insecure := flag.Bool("insecure", false, "skip TLS cert verification (dev only)")
	pskFile := flag.String("psk-file", "", "path to the shared-secret file (must match the server's) — required if the server has auth enabled")
	flag.Parse()

	var key []byte
	if *pskFile != "" {
		k, err := auth.LoadKey(*pskFile)
		if err != nil {
			log.Fatalf("load psk: %v", err)
		}
		key = k
	}

	if *mode == "tun" {
		runTunMode(*glueAddr, *insecure, *tunName, *tunMTU, *tunPaths, *tunMeasure, *tunMeasureInterval, key)
		return
	}

	if *mode == "droptest" {
		switch {
		case *dropCount > 0 && *dropPaths > 1:
			runDropMultipath(*dropAddr, *insecure, *dropCount, *dropInterval, *dropPaths, key)
		case *dropCount > 0:
			runDropStress(*dropAddr, *insecure, *dropCount, *dropInterval, key)
		default:
			runDropTest(*dropAddr, *insecure, key)
		}
		return
	}

	conn, err := transport.Dial(*serverAddr, *insecure)
	if err != nil {
		log.Fatalf("dial server: %v", err)
	}
	if key != nil {
		if err := auth.ClientHandshake(conn, key); err != nil {
			log.Fatalf("auth: %v", err)
		}
	}
	sess, err := smux.Client(conn, nil)
	if err != nil {
		log.Fatalf("smux client: %v", err)
	}
	log.Printf("connected to tunnel server %s", *serverAddr)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("socks5 listen: %v", err)
	}
	log.Printf("SOCKS5 proxy listening on %s", *listenAddr)

	for {
		appConn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleApp(appConn, sess)
	}
}

func handleApp(appConn net.Conn, sess *smux.Session) {
	defer appConn.Close()

	if err := socks5.Handshake(appConn); err != nil {
		log.Printf("socks5 handshake: %v", err)
		return
	}
	target, err := socks5.ReadRequest(appConn)
	if err != nil {
		log.Printf("socks5 request: %v", err)
		return
	}
	log.Printf("app requested %s", target)

	stream, err := sess.OpenStream()
	if err != nil {
		log.Printf("open stream: %v", err)
		socks5.WriteReply(appConn, false)
		return
	}
	defer stream.Close()

	if err := proto.WriteTarget(stream, target); err != nil {
		log.Printf("send target: %v", err)
		socks5.WriteReply(appConn, false)
		return
	}

	status := make([]byte, 1)
	if _, err := io.ReadFull(stream, status); err != nil || status[0] != 0 {
		log.Printf("server could not reach %s: %v", target, err)
		socks5.WriteReply(appConn, false)
		return
	}

	if err := socks5.WriteReply(appConn, true); err != nil {
		log.Printf("socks5 reply: %v", err)
		return
	}

	relay(appConn, stream)
	log.Printf("%s: closed", target)
}

func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// runDropTest sends a fixed sequence of frames over the droppable channel,
// injecting an artificial delay before some of them are written — standing
// in for "this frame got stuck behind a retransmit" without needing real
// packet loss. The server's TTL is 150ms (see cmd/server), so delays past
// that should show up there as drops.
func runDropTest(dropAddr string, insecure bool, key []byte) {
	conn, err := transport.Dial(dropAddr, insecure)
	if err != nil {
		log.Fatalf("dial droppable: %v", err)
	}
	defer conn.Close()
	if key != nil {
		if err := auth.ClientHandshake(conn, key); err != nil {
			log.Fatalf("auth: %v", err)
		}
	}
	if err := sendNewSessionID(conn); err != nil {
		log.Fatalf("send session id: %v", err)
	}
	log.Printf("connected to droppable channel %s", dropAddr)

	delays := []time.Duration{0, 0, 300 * time.Millisecond, 0, 400 * time.Millisecond, 0}
	for i, d := range delays {
		f := frame.New(uint32(i), []byte(fmt.Sprintf("frame #%d", i)))
		if d > 0 {
			log.Printf("frame %d: simulating %v delay before send", i, d)
			time.Sleep(d)
		}
		if _, err := conn.Write(f.Marshal()); err != nil {
			log.Printf("write frame %d: %v", i, err)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.Println("all frames sent")
	time.Sleep(300 * time.Millisecond)
}

// runDropStress sends count frames spaced by interval, with no artificial
// delay — under a lossy/jittery real connection (tc netem on the server
// side), some frames will genuinely arrive stale due to real TCP
// retransmission stalls, not a simulated sleep. Check the server's log
// for the accepted/DROPPED breakdown; this side just confirms what left
// the client.
func runDropStress(dropAddr string, insecure bool, count int, interval time.Duration, key []byte) {
	conn, err := transport.Dial(dropAddr, insecure)
	if err != nil {
		log.Fatalf("dial droppable: %v", err)
	}
	defer conn.Close()
	if key != nil {
		if err := auth.ClientHandshake(conn, key); err != nil {
			log.Fatalf("auth: %v", err)
		}
	}
	if err := sendNewSessionID(conn); err != nil {
		log.Fatalf("send session id: %v", err)
	}
	log.Printf("connected to droppable channel %s, sending %d frames every %v", dropAddr, count, interval)

	sent := 0
	for i := 0; i < count; i++ {
		f := frame.New(uint32(i), []byte(fmt.Sprintf("frame #%d", i)))
		if _, err := conn.Write(f.Marshal()); err != nil {
			log.Printf("write frame %d: %v (stopping)", i, err)
			break
		}
		sent++
		time.Sleep(interval)
	}
	log.Printf("done: %d/%d frames written to the connection (check server log for accepted/DROPPED)", sent, count)
	time.Sleep(300 * time.Millisecond)
}

// runDropMultipath opens `paths` independent TLS connections, all tagged
// with the same 8-byte session ID so the server can dedupe across them,
// and writes every frame to all of them — a cheap stand-in for real path
// diversity (see the ExitLag/multipath discussion): even sharing one
// physical uplink, each TCP connection draws netem's loss independently,
// so a frame only truly dies if it's unlucky on *every* path at once.
// sendNewSessionID generates a fresh random 8-byte session id and writes
// it as the header every droppable connection is now expected to send —
// required so the server's shared-receiver bookkeeping (used for
// multipath dedup) has a consistent handshake regardless of mode.
func sendNewSessionID(conn net.Conn) error {
	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		return err
	}
	_, err := conn.Write(sid)
	return err
}

func runDropMultipath(dropAddr string, insecure bool, count int, interval time.Duration, paths int, key []byte) {
	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		log.Fatalf("generate session id: %v", err)
	}
	log.Printf("multipath droptest: session %x, %d paths, %d frames every %v", sid, paths, count, interval)

	conns := make([]net.Conn, paths)
	for i := 0; i < paths; i++ {
		conn, err := transport.Dial(dropAddr, insecure)
		if err != nil {
			log.Fatalf("dial path %d: %v", i, err)
		}
		if key != nil {
			if err := auth.ClientHandshake(conn, key); err != nil {
				log.Fatalf("auth on path %d: %v", i, err)
			}
		}
		if _, err := conn.Write(sid); err != nil {
			log.Fatalf("send session id on path %d: %v", i, err)
		}
		conns[i] = conn
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < count; i++ {
		f := frame.New(uint32(i), []byte(fmt.Sprintf("frame #%d", i)))
		wire := f.Marshal()
		for pathIdx, c := range conns {
			if _, err := c.Write(wire); err != nil {
				log.Printf("frame %d: write failed on path %d: %v", i, pathIdx, err)
			}
		}
		time.Sleep(interval)
	}
	log.Printf("done: %d frames sent on all %d paths (check server log for the session summary)", count, paths)
	time.Sleep(300 * time.Millisecond)
}

// flowInfo remembers the original 4-tuple of a captured outbound packet
// so a reply can be turned back into a packet the OS will recognize as
// belonging to that same local socket.
type flowInfo struct {
	origSrc, origDst         [4]byte
	origSrcPort, origDstPort uint16
}

// runTunMode is the real integration: captures actual outbound UDP from
// a TUN interface, tunnels it through the glue channel, and reinjects
// whatever comes back so the OS (and the game/app that opened the local
// socket) sees an ordinary reply. IPv4 only — see internal/glue.
func runTunMode(glueAddr string, insecure bool, tunName string, mtu int, paths int, doMeasure bool, measureInterval time.Duration, key []byte) {
	if paths < 1 {
		paths = 1
	}
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	defer dev.Close()
	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, tunName, mtu)

	var stats *measure.Stats
	if doMeasure {
		stats = measure.New()
	}

	// One shared session id across all paths, so the server dedupes
	// duplicated copies against each other.
	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		log.Fatalf("generate session id: %v", err)
	}

	conns := make([]net.Conn, 0, paths)
	for i := 0; i < paths; i++ {
		c, err := transport.Dial(glueAddr, insecure)
		if err != nil {
			log.Fatalf("dial glue path %d: %v", i, err)
		}
		if key != nil {
			if err := auth.ClientHandshake(c, key); err != nil {
				log.Fatalf("auth on path %d: %v", i, err)
			}
		}
		if _, err := c.Write(sid); err != nil {
			log.Fatalf("send session id on path %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	log.Printf("connected to glue channel %s over %d path(s)", glueAddr, paths)

	var flowsMu sync.Mutex
	flows := make(map[uint16]flowInfo)

	// Replies come back duplicated across every path (server-side
	// broadcast), so a receiver dedupes them here before reinjecting —
	// otherwise the OS would see each reply N times.
	replyRecv := frame.NewReceiver(150 * time.Millisecond)
	var replyMu sync.Mutex

	// One reader goroutine per path.
	for _, c := range conns {
		go func(c net.Conn) {
			for {
				f, err := frame.ReadFrame(c)
				if err != nil {
					return
				}
				replyMu.Lock()
				ok, _ := replyRecv.Accept(f)
				replyMu.Unlock()
				if !ok {
					continue // duplicate copy from another path
				}

				// Measurement ping echo coming back — record RTT, don't
				// treat as UDP.
				if stats != nil {
					if nonce, isPing := glue.DecodePing(f.Payload); isPing {
						stats.OnRecv(nonce)
						continue
					}
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
				pkt := pktfilter.BuildIPv4UDP(fi.origDst, fi.origSrc, fi.origDstPort, fi.origSrcPort, payload)
				if _, err := dev.Write([][]byte{pkt}, 0); err != nil {
					log.Printf("TUN write: %v", err)
				}
			}
		}(c)
	}

	log.Println("waiting for outbound UDP to tunnel — bring the interface up and route real traffic through it")

	var seqMu sync.Mutex
	var seq uint32
	nextSeq := func() uint32 {
		seqMu.Lock()
		seq++
		v := seq
		seqMu.Unlock()
		return v
	}

	writeAllPaths := func(wire []byte) {
		for _, c := range conns {
			if _, err := c.Write(wire); err != nil {
				log.Printf("glue write: %v", err)
			}
		}
	}

	if stats != nil {
		var nonce uint64
		// ping sender
		go func() {
			ticker := time.NewTicker(measureInterval)
			defer ticker.Stop()
			for range ticker.C {
				nonce++
				stats.OnSend(nonce)
				wire := frame.New(nextSeq(), glue.EncodePing(nonce)).Marshal()
				writeAllPaths(wire)
			}
		}()
		// periodic summary
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				log.Printf("[measure %d-path] %s", paths, stats.Snapshot(time.Second).String())
			}
		}()
		log.Printf("measurement enabled: pinging every %v across %d path(s)", measureInterval, paths)
	}

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
			if !ok || info.Noise || info.Version != 4 || info.Proto != 17 || info.Payload == nil {
				continue
			}

			flowID := info.SrcPort
			var fi flowInfo
			copy(fi.origSrc[:], info.Src.To4())
			copy(fi.origDst[:], info.Dst.To4())
			fi.origSrcPort = info.SrcPort
			fi.origDstPort = info.DstPort

			flowsMu.Lock()
			flows[flowID] = fi
			flowsMu.Unlock()

			envelope := glue.EncodeOutbound(flowID, info.Dst, info.DstPort, info.Payload)
			wire := frame.New(nextSeq(), envelope).Marshal()
			writeAllPaths(wire)
		}
	}
}
