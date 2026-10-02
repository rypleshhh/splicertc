package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/config"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/sched"
	"tcp-dormtun/internal/transport"
)

// Config is server-config.json. Command line flags override it.
type Config struct {
	Addr        string `json:"addr,omitempty"`
	DropAddr    string `json:"drop_addr,omitempty"`
	GlueAddr    string `json:"glue_addr,omitempty"`
	VPNAddr     string `json:"vpn_addr,omitempty"`
	VPNTunName  string `json:"vpn_tun_name,omitempty"`
	VPNTunMTU   int    `json:"vpn_tun_mtu,omitempty"`
	VPNSubnet   string `json:"vpn_subnet,omitempty"`
	EgressIface string `json:"egress_iface,omitempty"`
	Cert        string `json:"cert,omitempty"`
	Key         string `json:"key,omitempty"`
	// list of client public keys, see authorized_keys.example.json
	AuthorizedKeysFile string `json:"authorized_keys_file,omitempty"`
	// speed limit server->client in Mbit/s, 0 = off
	VPNDownMbps float64 `json:"vpn_down_mbps,omitempty"`
}

// nil means auth is off
var authorizedKeys *auth.AuthorizedKeys

// Ban an IP for authBanDuration after maxAuthFailures failed logins.
const (
	maxAuthFailures = 3
	authBanDuration = 10 * time.Minute
)

var authFailures = struct {
	mu          sync.Mutex
	count       map[string]int
	bannedUntil map[string]time.Time
}{count: make(map[string]int), bannedUntil: make(map[string]time.Time)}

// authIP returns the remote IP without the port.
func authIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// checkAuthBan also removes expired bans.
func checkAuthBan(ip string) (until time.Time, banned bool) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	until, banned = authFailures.bannedUntil[ip]
	if !banned {
		return time.Time{}, false
	}
	if time.Now().After(until) {
		delete(authFailures.bannedUntil, ip)
		delete(authFailures.count, ip)
		return time.Time{}, false
	}
	return until, true
}

func recordAuthFailure(ip string) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	authFailures.count[ip]++
	if authFailures.count[ip] >= maxAuthFailures {
		until := time.Now().Add(authBanDuration)
		authFailures.bannedUntil[ip] = until
		log.Printf("auth: banning %s until %s after %d failed attempts", ip, until.Format(time.RFC3339), authFailures.count[ip])
	}
}

func recordAuthSuccess(ip string) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	delete(authFailures.count, ip)
	delete(authFailures.bannedUntil, ip)
}

// checkAuth runs the auth handshake (if enabled) and returns the client
// name. Must be called right after Accept.
func checkAuth(conn net.Conn) (name string, ok bool) {
	if authorizedKeys == nil {
		return "", true
	}

	ip := authIP(conn)
	if until, banned := checkAuthBan(ip); banned {
		log.Printf("auth: rejected %s: banned until %s (too many failed attempts)", conn.RemoteAddr(), until.Format(time.RFC3339))
		return "", false
	}

	name, err := auth.ServerHandshake(conn, authorizedKeys)
	if err != nil {
		log.Printf("auth: rejected %s: %v", conn.RemoteAddr(), err)
		recordAuthFailure(ip)
		return "", false
	}
	recordAuthSuccess(ip)
	return name, true
}

// dropSession is shared by all connections with the same session ID,
// so duplicates from parallel paths are detected.
type dropSession struct {
	mu         sync.Mutex
	recv       *frame.Receiver
	seen       map[uint32]struct{}
	accepted   int
	ttlDropped int // counts copies, not real loss with multipath
	duplicates int
}

var dropSessions = struct {
	mu sync.Mutex
	m  map[string]*dropSession
}{m: make(map[string]*dropSession)}

func getDropSession(id string) *dropSession {
	dropSessions.mu.Lock()
	defer dropSessions.mu.Unlock()
	s, ok := dropSessions.m[id]
	if !ok {
		s = &dropSession{recv: frame.NewReceiver(150 * time.Millisecond), seen: make(map[uint32]struct{})}
		dropSessions.m[id] = s
	}
	return s
}

// glueSession is shared by all paths with the same session ID.
// udpFlows are the UDP sockets to game servers, paths are the client
// connections replies are sent to.
type glueSession struct {
	mu       sync.Mutex
	recv     *frame.Receiver
	udpFlows map[uint16]*net.UDPConn
	paths    map[net.Conn]*sched.PathWriter
	replySeq uint32
}

// Queue size per glue path (~0.5s of game traffic). Older frames would
// be dropped by the client anyway (150ms TTL).
const (
	gluePathDepth  = 32
	glueStaleAfter = 150 * time.Millisecond
)

var glueSessions = struct {
	mu sync.Mutex
	m  map[string]*glueSession
}{m: make(map[string]*glueSession)}

func getGlueSession(id string) *glueSession {
	glueSessions.mu.Lock()
	defer glueSessions.mu.Unlock()
	s, ok := glueSessions.m[id]
	if !ok {
		s = &glueSession{
			recv:     frame.NewReceiver(150 * time.Millisecond),
			udpFlows: make(map[uint16]*net.UDPConn),
			paths:    make(map[net.Conn]*sched.PathWriter),
		}
		glueSessions.m[id] = s
	}
	return s
}

// broadcastPing sends a ping reply to all paths.
func (s *glueSession) broadcastPing(nonce uint64) {
	s.broadcast(func(seq uint32) []byte { return frame.New(seq, glue.EncodePing(nonce)).Marshal() })
}

// broadcastReply sends a reply to all paths.
func (s *glueSession) broadcastReply(flowID uint16, payload []byte) {
	s.broadcast(func(seq uint32) []byte { return frame.New(seq, glue.EncodeInbound(flowID, payload)).Marshal() })
}

// broadcast doesn't block. Dead paths are removed by handleGlueConn.
func (s *glueSession) broadcast(build func(seq uint32) []byte) {
	s.mu.Lock()
	seq := s.replySeq
	s.replySeq++
	writers := make([]*sched.PathWriter, 0, len(s.paths))
	for _, w := range s.paths {
		writers = append(writers, w)
	}
	s.mu.Unlock()

	wire := build(seq)
	for _, w := range writers {
		w.Send(wire)
	}
}

func main() {
	configPath := config.FindFlag(os.Args[1:], "config")
	if configPath == "" {
		configPath = "server-config.json"
	}
	var cfg Config
	foundCfg, err := config.Load(configPath, &cfg)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	addr := flag.String("addr", config.Str(cfg.Addr, ":8443"), "reliable channel listen address")
	dropAddr := flag.String("drop-addr", config.Str(cfg.DropAddr, ":8444"), "droppable channel listen address")
	glueAddr := flag.String("glue-addr", config.Str(cfg.GlueAddr, ":8446"), "glue channel listen address (real captured UDP traffic)")
	vpnAddr := flag.String("vpn-addr", config.Str(cfg.VPNAddr, ":8447"), "full-tunnel VPN channel listen address (all IP traffic, not just UDP)")
	vpnTunName := flag.String("vpn-tun-name", config.Str(cfg.VPNTunName, "dormvpn0"), "server-side TUN interface name for full-tunnel mode")
	vpnTunMTU := flag.Int("vpn-tun-mtu", config.Int(cfg.VPNTunMTU, 1400), "server-side TUN MTU for full-tunnel mode")
	vpnSubnet := flag.String("vpn-subnet", config.Str(cfg.VPNSubnet, "10.66.0.0/24"), "private subnet for the full-tunnel VPN (server=.1, client=.2)")
	egressIface := flag.String("egress-iface", cfg.EgressIface, "interface to MASQUERADE full-tunnel VPN egress traffic out of (empty = auto-detect via `ip route get`)")
	cert := flag.String("cert", config.Str(cfg.Cert, "devcerts/dev.crt"), "TLS cert file")
	key := flag.String("key", config.Str(cfg.Key, "devcerts/dev.key"), "TLS key file")
	authorizedKeysFile := flag.String("authorized-keys-file", cfg.AuthorizedKeysFile, "path to authorized_keys.json, empty = no auth")
	vpnDownMbps := flag.Float64("vpn-down-mbps", cfg.VPNDownMbps, "cap the vpn channel's server->client rate in Mbit/s, a bit below the client's real download speed (0 = no cap)")
	flag.String("config", configPath, "path to a JSON config file (server-config.json by default; explicit flags override its values)")
	flag.Parse()

	if foundCfg {
		log.Printf("loaded config from %s", configPath)
	}
	vpnDownRate = *vpnDownMbps
	if vpnDownRate > 0 {
		log.Printf("vpn: shaping server->client to %.1f Mbit/s", vpnDownRate)
	}

	if fp, err := transport.LoadCertFingerprint(*cert); err != nil {
		log.Printf("could not compute cert fingerprint for pinning: %v", err)
	} else {
		log.Printf("cert fingerprint (put this in the client's server_pin to enable pinning): %x", fp)
	}

	if *authorizedKeysFile != "" {
		keys, err := auth.LoadAuthorizedKeys(*authorizedKeysFile)
		if err != nil {
			log.Fatalf("load authorized keys: %v", err)
		}
		authorizedKeys = keys
		log.Printf("client authentication enabled (%s)", *authorizedKeysFile)
	} else {
		log.Println("WARNING: no authorized_keys_file, anyone can connect to this server!")
	}

	ln, err := transport.Listen(*addr, *cert, *key)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("reliable channel listening on %s", *addr)

	dropLn, err := transport.Listen(*dropAddr, *cert, *key)
	if err != nil {
		log.Fatalf("droppable listen: %v", err)
	}
	log.Printf("droppable channel listening on %s", *dropAddr)

	glueLn, err := transport.Listen(*glueAddr, *cert, *key)
	if err != nil {
		log.Fatalf("glue listen: %v", err)
	}
	log.Printf("glue channel listening on %s", *glueAddr)

	vpnLn, err := transport.Listen(*vpnAddr, *cert, *key)
	if err != nil {
		log.Fatalf("vpn listen: %v", err)
	}
	log.Printf("vpn channel listening on %s", *vpnAddr)

	vpnDev, _, _, _, err := setupVPNTun(*vpnTunName, *vpnTunMTU, *vpnSubnet, *egressIface)
	if err != nil {
		log.Fatalf("vpn tun setup: %v", err)
	}
	go vpnTunReader(vpnDev)

	go func() {
		for {
			conn, err := vpnLn.Accept()
			if err != nil {
				log.Printf("vpn accept: %v", err)
				continue
			}
			go handleVPNConn(conn, vpnDev)
		}
	}()

	go func() {
		for {
			conn, err := dropLn.Accept()
			if err != nil {
				log.Printf("droppable accept: %v", err)
				continue
			}
			go handleDroppableConn(conn)
		}
	}()

	go func() {
		for {
			conn, err := glueLn.Accept()
			if err != nil {
				log.Printf("glue accept: %v", err)
				continue
			}
			go handleGlueConn(conn)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

// handleDroppableConn uses its own connection, separate from smux, so a
// stall on one doesn't affect the other.
func handleDroppableConn(conn net.Conn) {
	defer conn.Close()
	name, ok := checkAuth(conn)
	if !ok {
		return
	}

	sidBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, sidBuf); err != nil {
		log.Printf("droppable: read session id: %v", err)
		return
	}
	sid := hex.EncodeToString(sidBuf)
	sess := getDropSession(sid)
	log.Printf("droppable path connected: %s (session %s, client %q)", conn.RemoteAddr(), sid, name)

	for {
		f, err := frame.ReadFrame(conn)
		if err != nil {
			sess.mu.Lock()
			a, t, d, total := sess.accepted, sess.ttlDropped, sess.duplicates, len(sess.seen)
			sess.mu.Unlock()
			lost := total - a
			lossPct := 0.0
			if total > 0 {
				lossPct = 100 * float64(lost) / float64(total)
			}
			log.Printf("droppable path closed (session %s): %v. summary: %d/%d unique frames delivered (%d never delivered = %.1f%% real loss); %d TTL-drop events, %d duplicate-suppressed copies",
				sid, err, a, total, lost, lossPct, t, d)
			return
		}
		age := time.Since(time.UnixMilli(f.TimestampMS))

		sess.mu.Lock()
		sess.seen[f.Seq] = struct{}{}
		ok, reason := sess.recv.Accept(f)
		switch {
		case ok:
			sess.accepted++
		case reason == "ttl exceeded":
			sess.ttlDropped++
		default:
			sess.duplicates++
		}
		sess.mu.Unlock()

		if ok {
			log.Printf("[session %s] frame %d accepted (age %v) via %s", sid, f.Seq, age, conn.RemoteAddr())
		} else {
			log.Printf("[session %s] frame %d dropped (%s, age %v) via %s", sid, f.Seq, reason, age, conn.RemoteAddr())
		}
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	name, ok := checkAuth(conn)
	if !ok {
		return
	}
	log.Printf("client connected: %s (%q)", conn.RemoteAddr(), name)

	sess, err := smux.Server(conn, nil)
	if err != nil {
		log.Printf("smux server: %v", err)
		return
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("session closed: %v", err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(s *smux.Stream) {
	defer s.Close()

	target, err := proto.ReadTarget(s)
	if err != nil {
		log.Printf("stream %d: read target: %v", s.ID(), err)
		return
	}
	log.Printf("stream %d: dialing %s", s.ID(), target)

	outConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("stream %d: dial %s failed: %v", s.ID(), target, err)
		s.Write([]byte{0x01})
		return
	}
	defer outConn.Close()

	if _, err := s.Write([]byte{0x00}); err != nil {
		log.Printf("stream %d: write status: %v", s.ID(), err)
		return
	}

	relay(s, outConn)
	log.Printf("stream %d: closed", s.ID())
}

func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// handleGlueConn relays UDP for the client. Several connections can have
// the same session ID (multipath), they share one glueSession.
func handleGlueConn(conn net.Conn) {
	defer conn.Close()
	name, ok := checkAuth(conn)
	if !ok {
		return
	}

	sidBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, sidBuf); err != nil {
		log.Printf("glue: read session id: %v", err)
		return
	}
	sid := hex.EncodeToString(sidBuf)
	sess := getGlueSession(sid)
	log.Printf("glue path connected: %s (session %s, client %q)", conn.RemoteAddr(), sid, name)

	writer := sched.NewPathWriter(conn, gluePathDepth, glueStaleAfter)
	sess.mu.Lock()
	sess.paths[conn] = writer
	nPaths := len(sess.paths)
	sess.mu.Unlock()
	log.Printf("glue path connected: %s (session %s, %d path(s) now)", conn.RemoteAddr(), sid, nPaths)

	defer func() {
		sess.mu.Lock()
		delete(sess.paths, conn)
		sess.mu.Unlock()
		writer.Close()
		if d := writer.Drops(); d > 0 {
			log.Printf("glue path %s: %d reply frame(s) dropped while this path was backed up (the other paths carried them)", conn.RemoteAddr(), d)
		}
	}()

	for {
		f, err := frame.ReadFrame(conn)
		if err != nil {
			log.Printf("glue: path closed (session %s): %v", sid, err)
			return
		}

		// pings: only check duplicates, not age
		if glue.IsPing(f.Payload) {
			sess.mu.Lock()
			ok, _ := sess.recv.AcceptSeq(f)
			sess.mu.Unlock()
			if ok {
				nonce, _ := glue.DecodePing(f.Payload)
				sess.broadcastPing(nonce)
			}
			continue
		}

		sess.mu.Lock()
		ok, _ := sess.recv.Accept(f)
		sess.mu.Unlock()
		if !ok {
			continue // duplicate or too old
		}

		flowID, dst, dstPort, payload, err := glue.DecodeOutbound(f.Payload)
		if err != nil {
			log.Printf("glue: decode: %v", err)
			continue
		}

		if ok, reason := glue.DestinationAllowed(dst, dstPort); !ok {
			log.Printf("glue: refusing to relay to %s:%d (%s)", dst, dstPort, reason)
			continue
		}

		sess.mu.Lock()
		udpConn, exists := sess.udpFlows[flowID]
		sess.mu.Unlock()

		if !exists {
			raddr := &net.UDPAddr{IP: dst, Port: int(dstPort)}
			udpConn, err = net.DialUDP("udp", nil, raddr)
			if err != nil {
				log.Printf("glue: dial UDP %s for flow %d: %v", raddr, flowID, err)
				continue
			}
			sess.mu.Lock()
			sess.udpFlows[flowID] = udpConn
			sess.mu.Unlock()
			log.Printf("glue: new flow %d -> %s (session %s)", flowID, raddr, sid)

			// read replies for this flow
			go func(flowID uint16, uc *net.UDPConn) {
				buf := make([]byte, 65535)
				for {
					n, err := uc.Read(buf)
					if err != nil {
						return
					}
					sess.broadcastReply(flowID, buf[:n])
				}
			}(flowID, udpConn)
		}

		if _, err := udpConn.Write(payload); err != nil {
			log.Printf("glue: write to UDP target for flow %d: %v", flowID, err)
		}
	}
}
