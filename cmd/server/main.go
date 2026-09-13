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

	"tcp-dormtun/internal/frame"
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
	accepted   int
	ttlDropped int // genuinely too late everywhere — real loss the mechanism couldn't save
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
		s = &dropSession{recv: frame.NewReceiver(150 * time.Millisecond)}
		dropSessions.m[id] = s
	}
	return s
}

func main() {
	addr := flag.String("addr", ":8443", "reliable channel listen address")
	dropAddr := flag.String("drop-addr", ":8444", "droppable channel listen address")
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
			a, t, d := sess.accepted, sess.ttlDropped, sess.duplicates
			sess.mu.Unlock()
			log.Printf("droppable path closed (session %s): %v — session summary so far: %d accepted, %d TTL-dropped (real loss), %d duplicate-suppressed (%.1f%% real drop rate)",
				sid, err, a, t, d, dropRate(a, t))
			return
		}
		age := time.Since(time.UnixMilli(f.TimestampMS))

		sess.mu.Lock()
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

// dropRate is the real, meaningful loss rate: accepted vs genuinely
// too-late-everywhere. Duplicate-suppressed frames are excluded on
// purpose — they're the expected cost of running N paths, not loss.
func dropRate(accepted, ttlDropped int) float64 {
	total := accepted + ttlDropped
	if total == 0 {
		return 0
	}
	return 100 * float64(ttlDropped) / float64(total)
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
