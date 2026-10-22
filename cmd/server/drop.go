package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tcp-dormtun/internal/frame"
)

// droppable channel: a test channel to see how frames get late or lost
// on the real network. Nothing is relayed, the server only logs.

// Don't remember more than this many frame numbers per session. Frames
// with other numbers after that are not counted at all, so the summary
// stays consistent (delivered <= seen).
const maxDropSeen = 100000

// dropSession is shared by all connections with the same session ID,
// so duplicates from parallel paths are detected.
type dropSession struct {
	mu         sync.Mutex
	recv       *frame.Receiver
	seen       map[uint32]struct{}
	accepted   int
	ttlDropped int // counts copies, not real loss with multipath
	duplicates int
	// frames with new numbers came after seen was full
	capHit     bool
	paths      int
	lastActive time.Time
}

var dropSessions = struct {
	mu sync.Mutex
	m  map[string]*dropSession
}{m: make(map[string]*dropSession)}

// getDropSession also counts the caller as a connected path, call
// leave() when it disconnects.
func getDropSession(id string) *dropSession {
	dropSessions.mu.Lock()
	defer dropSessions.mu.Unlock()
	s, ok := dropSessions.m[id]
	if !ok {
		s = &dropSession{recv: frame.NewReceiver(150 * time.Millisecond), seen: make(map[uint32]struct{})}
		dropSessions.m[id] = s
	}
	s.mu.Lock()
	s.paths++
	s.lastActive = time.Now()
	s.mu.Unlock()
	return s
}

func (s *dropSession) leave() {
	s.mu.Lock()
	s.paths--
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func cleanupDrop(now time.Time) {
	dropSessions.mu.Lock()
	defer dropSessions.mu.Unlock()
	for id, s := range dropSessions.m {
		s.mu.Lock()
		gone := s.paths == 0 && now.Sub(s.lastActive) > glueSessionIdle
		s.mu.Unlock()
		if gone {
			delete(dropSessions.m, id)
		}
	}
}

// handleDroppableConn uses its own connection, separate from smux, so a
// stall on one doesn't affect the other.
func handleDroppableConn(conn net.Conn) {
	defer conn.Close()
	startHandshake(conn)
	name, ok := checkAuth(conn)
	if !ok {
		return
	}

	sidBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, sidBuf); err != nil {
		log.Printf("droppable: read session id: %v", err)
		return
	}
	endHandshake(conn)
	sid := hex.EncodeToString(sidBuf)
	sess := getDropSession(sid)
	defer sess.leave()
	log.Printf("droppable path connected: %s (session %s, client %q)", conn.RemoteAddr(), sid, name)

	for {
		f, err := frame.ReadFrame(conn)
		if err != nil {
			log.Printf("droppable path closed (session %s): %v. summary: %s", sid, err, sess.summary())
			return
		}
		age := time.Since(time.UnixMilli(f.TimestampMS))
		ok, reason := sess.record(f)
		if ok {
			log.Printf("[session %s] frame %d accepted (age %v) via %s", sid, f.Seq, age, conn.RemoteAddr())
		} else {
			log.Printf("[session %s] frame %d dropped (%s, age %v) via %s", sid, f.Seq, reason, age, conn.RemoteAddr())
		}
	}
}

// record runs f through the receiver and counts the result. Only frames
// whose number is (or fits) in seen are counted.
func (s *dropSession) record(f frame.Frame) (ok bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.seen[f.Seq]
	counted := known || len(s.seen) < maxDropSeen
	if counted {
		s.seen[f.Seq] = struct{}{}
	} else {
		s.capHit = true
	}
	ok, reason = s.recv.Accept(f)
	if !counted {
		return ok, reason
	}
	switch {
	case ok:
		s.accepted++
	case reason == "ttl exceeded":
		s.ttlDropped++
	default:
		s.duplicates++
	}
	return ok, reason
}

func (s *dropSession) summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := len(s.seen)
	lost := total - s.accepted
	lossPct := 0.0
	if total > 0 {
		lossPct = 100 * float64(lost) / float64(total)
	}
	out := fmt.Sprintf("%d/%d unique frames delivered (%d never delivered = %.1f%% real loss); %d TTL-drop events, %d duplicate-suppressed copies",
		s.accepted, total, lost, lossPct, s.ttlDropped, s.duplicates)
	if s.capHit {
		out += fmt.Sprintf(" (only the first %d frame numbers were counted)", maxDropSeen)
	}
	return out
}
