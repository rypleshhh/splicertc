package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/config"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/measure"
	"tcp-dormtun/internal/pktfilter"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/socks5"
	"tcp-dormtun/internal/transport"
)

// Config mirrors the client's flags — every field optional. A CLI flag,
// if explicitly passed, always overrides the matching field here.
type Config struct {
	Mode               string `json:"mode,omitempty"`
	Listen             string `json:"listen,omitempty"`
	Server             string `json:"server,omitempty"`
	DropAddr           string `json:"drop_addr,omitempty"`
	GlueAddr           string `json:"glue_addr,omitempty"`
	TunName            string `json:"tun_name,omitempty"`
	TunMTU             int    `json:"tun_mtu,omitempty"`
	TunPaths           int    `json:"tun_paths,omitempty"`
	TunMeasure         bool   `json:"tun_measure,omitempty"`
	TunMeasureInterval string `json:"tun_measure_interval,omitempty"` // e.g. "33ms"
	VPNAddr            string `json:"vpn_addr,omitempty"`
	VPNTunName         string `json:"vpn_tun_name,omitempty"`
	VPNTunMTU          int    `json:"vpn_tun_mtu,omitempty"`
	// GameProcesses selectively routes matched processes' UDP traffic
	// through the glue channel (multipath duplication) instead of vpn
	// mode's single TCP stream — see runVPNMode. Empty means vpn mode
	// behaves exactly as before (no glue connections opened at all).
	GameProcesses []string `json:"game_processes,omitempty"`
	// GamePaths is the multipath duplication factor for GameProcesses'
	// UDP traffic; defaults to 3 if GameProcesses is set but this isn't.
	GamePaths int `json:"game_paths,omitempty"`
	DropCount          int    `json:"drop_count,omitempty"`
	DropInterval       string `json:"drop_interval,omitempty"` // e.g. "33ms"
	DropPaths          int    `json:"drop_paths,omitempty"`
	Insecure           bool   `json:"insecure,omitempty"`
	// ServerPin is the SHA-256 (hex) of the server's TLS certificate,
	// printed by the server at startup. When set, the client verifies
	// the server presents exactly this certificate instead of trusting
	// insecure's "accept anything" — without a pin, insecure:true is
	// vulnerable to a TLS-intercepting middlebox reading all traffic.
	ServerPin string `json:"server_pin,omitempty"`
	PSKFile   string `json:"psk_file,omitempty"`
	// PSK is the shared secret written directly into the config file,
	// as an alternative to -psk-file/PSKFile. Keep the config file out
	// of git if it holds a real secret (see config.example.json vs
	// config.json).
	PSK string `json:"psk,omitempty"`
}

// parseGameProcesses turns a comma-separated -game-processes value into
// a normalized (lowercase, trimmed, empty entries dropped) list, ready
// to compare directly against procmap's already-lowercase process names.
func parseGameProcesses(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Fatalf("config: invalid duration %q: %v", s, err)
	}
	return d
}

func main() {
	configPath := config.FindFlag(os.Args[1:], "config")
	if configPath == "" {
		configPath = "client-config.json"
	}
	var cfg Config
	foundCfg, err := config.Load(configPath, &cfg)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	mode := flag.String("mode", config.Str(cfg.Mode, "socks5"), "socks5 (default), droptest, tun, or vpn")
	listenAddr := flag.String("listen", config.Str(cfg.Listen, "127.0.0.1:1080"), "SOCKS5 listen address")
	serverAddr := flag.String("server", config.Str(cfg.Server, "127.0.0.1:8443"), "tunnel server address")
	dropAddr := flag.String("drop-addr", config.Str(cfg.DropAddr, "127.0.0.1:8444"), "droppable channel address (droptest mode)")
	glueAddr := flag.String("glue-addr", config.Str(cfg.GlueAddr, "127.0.0.1:8446"), "glue channel address (tun mode)")
	tunName := flag.String("tun-name", config.Str(cfg.TunName, "dormtun0"), "TUN interface name (tun mode)")
	tunMTU := flag.Int("tun-mtu", config.Int(cfg.TunMTU, 1420), "TUN interface MTU (tun mode)")
	tunPaths := flag.Int("tun-paths", config.Int(cfg.TunPaths, 1), "tun mode: number of parallel duplicated paths (1 = no duplication)")
	tunMeasure := flag.Bool("tun-measure", cfg.TunMeasure, "tun mode: send measurement pings and print RTT/jitter/loss periodically")
	tunMeasureInterval := flag.Duration("tun-measure-interval", parseDurationOr(cfg.TunMeasureInterval, 33*time.Millisecond), "tun mode: spacing between measurement pings")
	vpnAddr := flag.String("vpn-addr", config.Str(cfg.VPNAddr, "127.0.0.1:8447"), "full-tunnel VPN channel address (vpn mode)")
	vpnTunName := flag.String("vpn-tun-name", config.Str(cfg.VPNTunName, "dormvpn0"), "TUN interface name (vpn mode)")
	vpnTunMTU := flag.Int("vpn-tun-mtu", config.Int(cfg.VPNTunMTU, 1400), "TUN interface MTU (vpn mode)")
	dropCount := flag.Int("drop-count", cfg.DropCount, "droptest: if >0, send this many frames at -drop-interval spacing instead of the fixed delay demo")
	dropInterval := flag.Duration("drop-interval", parseDurationOr(cfg.DropInterval, 33*time.Millisecond), "droptest: spacing between frames in stress mode (33ms ~ 30 ticks/sec, like a game sending state updates)")
	dropPaths := flag.Int("drop-paths", config.Int(cfg.DropPaths, 1), "droptest stress mode: number of parallel TLS connections to duplicate each frame across")
	insecure := flag.Bool("insecure", cfg.Insecure, "skip TLS cert verification (dev only)")
	serverPin := flag.String("server-pin", cfg.ServerPin, "SHA-256 (hex) of the server's TLS certificate — when set, the server must present exactly this cert (see -insecure's caveat about MITM otherwise)")
	gameProcessesFlag := flag.String("game-processes", strings.Join(cfg.GameProcesses, ","), "vpn mode: comma-separated executable names (e.g. deadlock.exe) whose UDP traffic gets routed through the glue channel with multipath duplication instead of the single vpn stream")
	gamePaths := flag.Int("game-paths", config.Int(cfg.GamePaths, 0), "vpn mode: multipath duplication factor for -game-processes UDP traffic (0 = default of 3 if -game-processes is set)")
	pskFile := flag.String("psk-file", cfg.PSKFile, "path to the shared-secret file (must match the server's) — required if the server has auth enabled")
	flag.String("config", configPath, "path to a JSON config file (client-config.json by default; explicit flags override its values)")
	flag.Parse()

	if foundCfg {
		log.Printf("loaded config from %s", configPath)
	}

	var key []byte
	switch {
	case *pskFile != "":
		k, err := auth.LoadKey(*pskFile)
		if err != nil {
			log.Fatalf("load psk: %v", err)
		}
		key = k
	case cfg.PSK != "":
		key = auth.DeriveKey(cfg.PSK)
	}

	var pin []byte
	if *serverPin != "" {
		p, err := hex.DecodeString(*serverPin)
		if err != nil {
			log.Fatalf("server-pin: invalid hex: %v", err)
		}
		pin = p
	}

	if *mode == "tun" {
		runTunMode(*glueAddr, *insecure, pin, *tunName, *tunMTU, *tunPaths, *tunMeasure, *tunMeasureInterval, key)
		return
	}

	if *mode == "vpn" {
		gameProcesses := parseGameProcesses(*gameProcessesFlag)
		paths := *gamePaths
		if len(gameProcesses) > 0 && paths <= 0 {
			paths = 3
		}
		runVPNMode(*vpnAddr, *insecure, pin, *vpnTunName, *vpnTunMTU, key, *glueAddr, gameProcesses, paths)
		return
	}

	if *mode == "droptest" {
		switch {
		case *dropCount > 0 && *dropPaths > 1:
			runDropMultipath(*dropAddr, *insecure, pin, *dropCount, *dropInterval, *dropPaths, key)
		case *dropCount > 0:
			runDropStress(*dropAddr, *insecure, pin, *dropCount, *dropInterval, key)
		default:
			runDropTest(*dropAddr, *insecure, pin, key)
		}
		return
	}

	conn, err := transport.Dial(*serverAddr, *insecure, pin)
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
func runDropTest(dropAddr string, insecure bool, pin []byte, key []byte) {
	conn, err := transport.Dial(dropAddr, insecure, pin)
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
func runDropStress(dropAddr string, insecure bool, pin []byte, count int, interval time.Duration, key []byte) {
	conn, err := transport.Dial(dropAddr, insecure, pin)
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

func runDropMultipath(dropAddr string, insecure bool, pin []byte, count int, interval time.Duration, paths int, key []byte) {
	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		log.Fatalf("generate session id: %v", err)
	}
	log.Printf("multipath droptest: session %x, %d paths, %d frames every %v", sid, paths, count, interval)

	conns := make([]net.Conn, paths)
	for i := 0; i < paths; i++ {
		conn, err := transport.Dial(dropAddr, insecure, pin)
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

// flowKey identifies one UDP flow by its full 4-tuple. Keying only by
// source port (the old scheme) collapses distinct flows whenever one
// local socket talks to more than one remote destination — routine for
// Steam Datagram Relay, which pings many relay POPs from a single UDP
// socket. The server trusts flowID as an opaque handle and never
// second-guesses it (see cmd/server/main.go handleGlueConn), so once
// two different destinations shared an ID, later traffic for one
// destination could get silently written to the other's socket.
type flowKey struct {
	srcPort uint16
	dst     [4]byte
	dstPort uint16
}

// allocFlowID returns the flow ID already assigned to key, or allocates
// the next free one. uint16 gives 65536 concurrent flows — several
// orders of magnitude more than a real gaming session touches, so IDs
// are safe to leave unreclaimed here (idle expiry is a separate,
// already-tracked improvement, not a correctness requirement for this
// fix: the bug was that two different destinations could collide on
// the same ID, not that IDs are ever reused today).
func allocFlowID(ids map[flowKey]uint16, counter *uint16, key flowKey) uint16 {
	if id, ok := ids[key]; ok {
		return id
	}
	*counter++
	ids[key] = *counter
	return *counter
}

// runTunMode is the real integration: captures actual outbound UDP from
// a TUN interface, tunnels it through the glue channel, and reinjects
// whatever comes back so the OS (and the game/app that opened the local
// socket) sees an ordinary reply. IPv4 only — see internal/glue.
func runTunMode(glueAddr string, insecure bool, pin []byte, tunName string, mtu int, paths int, doMeasure bool, measureInterval time.Duration, key []byte) {
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
		c, err := transport.Dial(glueAddr, insecure, pin)
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
	flowIDs := make(map[flowKey]uint16)
	var flowIDCounter uint16

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
				// Measurement ping echo coming back — record RTT
				// regardless of how stale it looks; duplicate copies
				// from other multipath paths are already handled by
				// stats.OnRecv (first arrival wins, nonce removed).
				if nonce, isPing := glue.DecodePing(f.Payload); isPing {
					if stats != nil {
						stats.OnRecv(nonce)
					}
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

			var fi flowInfo
			copy(fi.origSrc[:], info.Src.To4())
			copy(fi.origDst[:], info.Dst.To4())
			fi.origSrcPort = info.SrcPort
			fi.origDstPort = info.DstPort

			key := flowKey{srcPort: info.SrcPort, dst: fi.origDst, dstPort: info.DstPort}

			flowsMu.Lock()
			flowID := allocFlowID(flowIDs, &flowIDCounter, key)
			flows[flowID] = fi
			flowsMu.Unlock()

			envelope := glue.EncodeOutbound(flowID, info.Dst, info.DstPort, info.Payload)
			wire := frame.New(nextSeq(), envelope).Marshal()
			writeAllPaths(wire)
		}
	}
}
