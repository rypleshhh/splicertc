package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/transport"
)

// authKey is nil when auth is disabled (explicitly, via an empty
// -psk-file) — checkAuth becomes a no-op in that case.
var authKey []byte

// checkAuth runs the challenge-response handshake if auth is enabled.
// Call this first thing after Accept, before any protocol-specific
// logic — an unauthenticated connection shouldn't get far enough to
// open a SOCKS5 tunnel, occupy a droppable session, or relay UDP.
func checkAuth(conn net.Conn) bool {
	if authKey == nil {
		return true
	}
	if err := auth.ServerHandshake(conn, authKey); err != nil {
		log.Printf("auth: rejected %s: %v", conn.RemoteAddr(), err)
		return false
	}
	return true
}

// dropSession is shared by every connection that presents the same
// session ID — that's what lets N parallel "duplicate" connections
// dedupe against each other instead of each pretending every frame
// it sees is new.
type dropSession struct {
	mu         sync.Mutex
	recv       *frame.Receiver
	seen       map[uint32]struct{} // distinct frames ever observed, regardless of outcome
	accepted   int
	ttlDropped int // copy-level count — informative, but NOT the real loss rate under multipath
	duplicates int // arrived after a fresher/earlier copy already won — expected cost of duplication, not loss
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

// glueSession is shared by all parallel paths carrying the same session
// ID. The dedup receiver rejects duplicate copies of a frame that
// arrived on more than one path; udpFlows are the real sockets out to
// game servers; paths is the set of currently-connected client
// connections, any/all of which a reply can be duplicated back over.
type glueSession struct {
	mu       sync.Mutex
	recv     *frame.Receiver
	udpFlows map[uint16]*net.UDPConn
	paths    map[net.Conn]struct{}
	replySeq uint32
}

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
			paths:    make(map[net.Conn]struct{}),
		}
		glueSessions.m[id] = s
	}
	return s
}

// broadcastPing echoes a measurement ping back over every live path.
func (s *glueSession) broadcastPing(nonce uint64) {
	s.mu.Lock()
	seq := s.replySeq
	s.replySeq++
	paths := make([]net.Conn, 0, len(s.paths))
	for c := range s.paths {
		paths = append(paths, c)
	}
	s.mu.Unlock()

	wire := frame.New(seq, glue.EncodePing(nonce)).Marshal()
	for _, c := range paths {
		if _, err := c.Write(wire); err != nil {
			s.mu.Lock()
			delete(s.paths, c)
			s.mu.Unlock()
		}
	}
}

// broadcastReply duplicates one reply frame across every currently
// connected path for this session. Under multipath that's the same
// loss-hedging in the server->client direction as the client does
// client->server. Dead paths are dropped from the set.
func (s *glueSession) broadcastReply(flowID uint16, payload []byte) {
	s.mu.Lock()
	seq := s.replySeq
	s.replySeq++
	paths := make([]net.Conn, 0, len(s.paths))
	for c := range s.paths {
		paths = append(paths, c)
	}
	s.mu.Unlock()

	wire := frame.New(seq, glue.EncodeInbound(flowID, payload)).Marshal()
	for _, c := range paths {
		if _, err := c.Write(wire); err != nil {
			s.mu.Lock()
			delete(s.paths, c)
			s.mu.Unlock()
		}
	}
}

func main() {
	addr := flag.String("addr", ":8443", "reliable channel listen address")
	dropAddr := flag.String("drop-addr", ":8444", "droppable channel listen address")
	glueAddr := flag.String("glue-addr", ":8446", "glue channel listen address (real captured UDP traffic)")
	cert := flag.String("cert", "devcerts/dev.crt", "TLS cert file")
	key := flag.String("key", "devcerts/dev.key", "TLS key file")
	pskFile := flag.String("psk-file", "", "path to a shared-secret file clients must know to use this server (leave empty to disable auth — NOT recommended for anything reachable from the internet)")
	flag.Parse()

	if *pskFile != "" {
		k, err := auth.LoadKey(*pskFile)
		if err != nil {
			log.Fatalf("load psk: %v", err)
		}
		authKey = k
		log.Println("client authentication enabled")
	} else {
		log.Println("!!! WARNING: no -psk-file given — this server accepts connections from ANYONE who finds it. It can be used as an open proxy or a UDP relay for amplification attacks. Set -psk-file before exposing this to the internet.")
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

// handleDroppableConn is deliberately separate from the smux/SOCKS5 path:
// its own TLS connection, its own accept loop, no shared state. That's
// the point — a stall on the reliable side must never affect this one,
// and vice versa.
func handleDroppableConn(conn net.Conn) {
	defer conn.Close()
	if !checkAuth(conn) {
		return
	}

	sidBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, sidBuf); err != nil {
		log.Printf("droppable: read session id: %v", err)
		return
	}
	sid := hex.EncodeToString(sidBuf)
	sess := getDropSession(sid)
	log.Printf("droppable path connected: %s (session %s)", conn.RemoteAddr(), sid)

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
			log.Printf("droppable path closed (session %s): %v — session summary so far: %d/%d unique frames delivered (%d never delivered = %.1f%% real loss); %d TTL-drop events, %d duplicate-suppressed copies",
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
	if !checkAuth(conn) {
		return
	}
	log.Printf("client connected: %s", conn.RemoteAddr())

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

// handleGlueConn carries real captured UDP traffic (see internal/glue).
// Multiple parallel connections can share one session ID (multipath):
// they join a common glueSession so a frame duplicated across paths is
// only acted on once, replies fan back out over every live path, and
// all paths share one real UDP socket per flow. Single-path use (one
// connection per session) is just the degenerate case.
func handleGlueConn(conn net.Conn) {
	defer conn.Close()
	if !checkAuth(conn) {
		return
	}

	sidBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, sidBuf); err != nil {
		log.Printf("glue: read session id: %v", err)
		return
	}
	sid := hex.EncodeToString(sidBuf)
	sess := getGlueSession(sid)

	sess.mu.Lock()
	sess.paths[conn] = struct{}{}
	nPaths := len(sess.paths)
	sess.mu.Unlock()
	log.Printf("glue path connected: %s (session %s, %d path(s) now)", conn.RemoteAddr(), sid, nPaths)

	defer func() {
		sess.mu.Lock()
		delete(sess.paths, conn)
		sess.mu.Unlock()
	}()

	for {
		f, err := frame.ReadFrame(conn)
		if err != nil {
			log.Printf("glue: path closed (session %s): %v", sid, err)
			return
		}

		sess.mu.Lock()
		ok, _ := sess.recv.Accept(f)
		sess.mu.Unlock()
		if !ok {
			continue // duplicate copy from another path, or stale — already handled
		}

		// Measurement ping: echo it straight back over all paths, don't
		// treat it as UDP-carrying.
		if glue.IsPing(f.Payload) {
			nonce, _ := glue.DecodePing(f.Payload)
			sess.broadcastPing(nonce)
			continue
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

			// One reader per flow, shipping replies back across all paths.
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
