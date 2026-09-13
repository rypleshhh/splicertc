package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/transport"
)

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

func main() {
	addr := flag.String("addr", ":8443", "reliable channel listen address")
	dropAddr := flag.String("drop-addr", ":8444", "droppable channel listen address")
	glueAddr := flag.String("glue-addr", ":8446", "glue channel listen address (real captured UDP traffic)")
	cert := flag.String("cert", "devcerts/dev.crt", "TLS cert file")
	key := flag.String("key", "devcerts/dev.key", "TLS key file")
	flag.Parse()

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

// handleGlueConn carries real captured UDP traffic (see internal/glue):
// each distinct flow ID gets its own real net.UDPConn to the requested
// destination, dialed lazily on first use. A per-flow goroutine reads
// whatever comes back and ships it to the client as a new frame. Several
// of those goroutines can be writing to the same underlying connection
// concurrently, so writes go through writeMu — frame bytes must not
// interleave.
func handleGlueConn(conn net.Conn) {
	defer conn.Close()

	sidBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, sidBuf); err != nil {
		log.Printf("glue: read session id: %v", err)
		return
	}
	sid := hex.EncodeToString(sidBuf)
	log.Printf("glue client connected: %s (session %s)", conn.RemoteAddr(), sid)

	recv := frame.NewReceiver(150 * time.Millisecond)

	var writeMu sync.Mutex
	var replySeq uint32

	var flowsMu sync.Mutex
	flows := make(map[uint16]*net.UDPConn)

	defer func() {
		flowsMu.Lock()
		for _, uc := range flows {
			uc.Close()
		}
		flowsMu.Unlock()
	}()

	for {
		f, err := frame.ReadFrame(conn)
		if err != nil {
			log.Printf("glue: connection closed (session %s): %v", sid, err)
			return
		}
		if ok, reason := recv.Accept(f); !ok {
			log.Printf("glue: frame dropped (%s)", reason)
			continue
		}

		flowID, dst, dstPort, payload, err := glue.DecodeOutbound(f.Payload)
		if err != nil {
			log.Printf("glue: decode: %v", err)
			continue
		}

		flowsMu.Lock()
		udpConn, exists := flows[flowID]
		flowsMu.Unlock()

		if !exists {
			raddr := &net.UDPAddr{IP: dst, Port: int(dstPort)}
			udpConn, err = net.DialUDP("udp", nil, raddr)
			if err != nil {
				log.Printf("glue: dial UDP %s for flow %d: %v", raddr, flowID, err)
				continue
			}
			flowsMu.Lock()
			flows[flowID] = udpConn
			flowsMu.Unlock()
			log.Printf("glue: new flow %d -> %s", flowID, raddr)

			go func(flowID uint16, uc *net.UDPConn) {
				buf := make([]byte, 65535)
				for {
					n, err := uc.Read(buf)
					if err != nil {
						return
					}
					seq := atomic.AddUint32(&replySeq, 1)
					reply := frame.New(seq, glue.EncodeInbound(flowID, buf[:n]))
					writeMu.Lock()
					_, werr := conn.Write(reply.Marshal())
					writeMu.Unlock()
					if werr != nil {
						return
					}
				}
			}(flowID, udpConn)
		}

		if _, err := udpConn.Write(payload); err != nil {
			log.Printf("glue: write to UDP target for flow %d: %v", flowID, err)
		}
	}
}
