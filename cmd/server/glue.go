package main

import (
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/sched"
	"tcp-dormtun/internal/transport"
)

// glueSession is shared by all paths with the same session ID.
// udpFlows are the UDP sockets to game servers, paths are the client
// connections replies are sent to.
type glueSession struct {
	// client name from authorized_keys.json, another client can't join
	owner string

	mu       sync.Mutex
	recv     *frame.Receiver
	udpFlows map[uint16]*udpFlow
	paths    map[net.Conn]*sched.PathWriter
	replySeq uint32
	// when the last path went away, zero while there are paths
	emptySince time.Time
	// so the flow limit is logged once, not for every packet
	flowLimitLogged bool
}

// udpFlow is one UDP socket to a game server.
type udpFlow struct {
	conn     *net.UDPConn
	dst      string
	lastSeen time.Time
}

// Queue size per glue path (~0.5s of game traffic). Older frames would
// be dropped by the client anyway (150ms TTL).
const (
	gluePathDepth  = 32
	glueStaleAfter = 150 * time.Millisecond
	// client sends a path ping every 200ms, so 10s of silence = dead path
	glueReadTimeout = 10 * time.Second
	// small unsent-data limit for glue sockets, game packets are tiny
	glueNotSentLowat = 4 * 1024
)

// Limits, so one client (or a bug in it) can't eat all sockets and memory.
// A game uses a handful of flows; every flow is a socket, a goroutine and
// a 64 KB read buffer.
const (
	maxFlowsPerSession   = 512
	maxGlueSessions      = 256
	maxSessionsPerClient = 4
	maxPathsPerSession   = 8
	// all sessions together: 4096 sockets and at most 256 MB of buffers
	maxTotalFlows = 4096
)

// totalFlows counts open flow sockets of all sessions.
var totalFlows atomic.Int64

// Cleanup: flows with no packets either way and sessions with no paths
// are removed after this long.
const (
	glueFlowIdle    = 2 * time.Minute
	glueSessionIdle = 2 * time.Minute
	janitorInterval = 30 * time.Second
)

var glueSessions = struct {
	mu sync.Mutex
	m  map[string]*glueSession
}{m: make(map[string]*glueSession)}

// attachGluePath finds or creates the session and adds the path to it.
// Both happen under glueSessions.mu so the janitor can't delete the
// session in between. ok is false if the session belongs to another
// client or a limit is reached.
func attachGluePath(id, owner string, conn net.Conn, w *sched.PathWriter) (s *glueSession, paths int, ok bool) {
	glueSessions.mu.Lock()
	defer glueSessions.mu.Unlock()
	s, exists := glueSessions.m[id]
	if !exists {
		if !makeRoomForSession(owner) {
			log.Printf("glue: %q already has %d active sessions, rejecting %s", owner, maxSessionsPerClient, conn.RemoteAddr())
			return nil, 0, false
		}
		if len(glueSessions.m) >= maxGlueSessions {
			log.Printf("glue: too many sessions (%d), rejecting %s", maxGlueSessions, conn.RemoteAddr())
			return nil, 0, false
		}
		s = &glueSession{
			owner:    owner,
			recv:     frame.NewReceiver(150 * time.Millisecond),
			udpFlows: make(map[uint16]*udpFlow),
			paths:    make(map[net.Conn]*sched.PathWriter),
		}
		glueSessions.m[id] = s
	}
	if s.owner != owner {
		log.Printf("glue: session %s belongs to %q, rejecting %q from %s", id, s.owner, owner, conn.RemoteAddr())
		return nil, 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.paths) >= maxPathsPerSession {
		log.Printf("glue: session %s already has %d paths, rejecting %s", id, maxPathsPerSession, conn.RemoteAddr())
		return nil, 0, false
	}
	s.paths[conn] = w
	s.emptySince = time.Time{}
	return s, len(s.paths), true
}

// makeRoomForSession checks the per-client session limit. Sessions of a
// restarted client linger for glueSessionIdle without paths; those are
// removed first to make room. Called with glueSessions.mu held.
func makeRoomForSession(owner string) bool {
	var count int
	var oldestID string
	var oldest *glueSession
	var oldestSince time.Time
	for id, s := range glueSessions.m {
		if s.owner != owner {
			continue
		}
		count++
		s.mu.Lock()
		empty := len(s.paths) == 0
		since := s.emptySince
		s.mu.Unlock()
		if empty && (oldest == nil || since.Before(oldestSince)) {
			oldestID, oldest, oldestSince = id, s, since
		}
	}
	if count < maxSessionsPerClient {
		return true
	}
	if oldest == nil {
		return false // all of them are in use
	}
	oldest.mu.Lock()
	oldest.closeAllFlowsLocked()
	oldest.mu.Unlock()
	delete(glueSessions.m, oldestID)
	return true
}

// closeFlowLocked closes one flow socket (its reader goroutine ends).
// Called with s.mu held.
func (s *glueSession) closeFlowLocked(flowID uint16, f *udpFlow) {
	f.conn.Close()
	delete(s.udpFlows, flowID)
	totalFlows.Add(-1)
}

func (s *glueSession) closeAllFlowsLocked() {
	for id, f := range s.udpFlows {
		s.closeFlowLocked(id, f)
	}
}

func (s *glueSession) detachPath(conn net.Conn) {
	s.mu.Lock()
	delete(s.paths, conn)
	if len(s.paths) == 0 {
		s.emptySince = time.Now()
	}
	s.mu.Unlock()
}

// flow returns the UDP socket for flowID. If the client reused flowID for
// another destination, the old socket is closed and a new one is made.
// Everything is done under s.mu so two paths can't create two sockets
// for the same flow (DialUDP doesn't send anything, it's fast).
func (s *glueSession) flow(sid string, flowID uint16, dst net.IP, dstPort uint16) (*net.UDPConn, error) {
	raddr := &net.UDPAddr{IP: dst, Port: int(dstPort)}
	key := raddr.String()
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.udpFlows[flowID]; ok {
		if f.dst == key {
			f.lastSeen = now
			return f.conn, nil
		}
		log.Printf("glue: flow %d changed its destination (session %s)", flowID, sid)
		s.closeFlowLocked(flowID, f)
	}
	if len(s.udpFlows) >= maxFlowsPerSession || totalFlows.Load() >= maxTotalFlows {
		if !s.flowLimitLogged {
			s.flowLimitLogged = true
			log.Printf("glue: session %s hit the flow limit (%d per session, %d in total), new flows are dropped", sid, maxFlowsPerSession, maxTotalFlows)
		}
		return nil, errTooManyFlows
	}

	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	f := &udpFlow{conn: uc, dst: key, lastSeen: now}
	s.udpFlows[flowID] = f
	totalFlows.Add(1)
	// no address in the log: it shouldn't be a list of the client's servers
	log.Printf("glue: new flow %d (session %s)", flowID, sid)

	// read replies for this flow until the socket is closed
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			f.lastSeen = time.Now()
			s.mu.Unlock()
			s.broadcastReply(flowID, buf[:n])
		}
	}()
	return uc, nil
}

var errTooManyFlows = errors.New("too many flows in this session")

// broadcastPing sends a ping reply to all paths.
func (s *glueSession) broadcastPing(nonce uint64) {
	s.broadcast(func(seq uint32) []byte { return frame.New(seq, glue.EncodePing(nonce)).Marshal() })
}

// broadcastReply sends a reply to all paths. A reply that doesn't fit in
// one frame is dropped (it would break the stream framing).
func (s *glueSession) broadcastReply(flowID uint16, payload []byte) {
	if len(payload) > glue.MaxInboundPayload {
		return
	}
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

// cleanupGlue removes idle flows and sessions nobody is connected to.
func cleanupGlue(now time.Time) {
	glueSessions.mu.Lock()
	defer glueSessions.mu.Unlock()
	for id, s := range glueSessions.m {
		s.mu.Lock()
		for flowID, f := range s.udpFlows {
			if now.Sub(f.lastSeen) > glueFlowIdle {
				s.closeFlowLocked(flowID, f)
			}
		}
		gone := len(s.paths) == 0 && !s.emptySince.IsZero() && now.Sub(s.emptySince) > glueSessionIdle
		if gone {
			s.closeAllFlowsLocked()
		}
		s.mu.Unlock()
		if gone {
			delete(glueSessions.m, id)
			log.Printf("glue: session %s removed (no paths for %v)", id, glueSessionIdle)
		}
	}
}

// handleGlueConn relays UDP for the client. Several connections can have
// the same session ID (multipath), they share one glueSession.
func handleGlueConn(conn net.Conn) {
	defer conn.Close()
	startHandshake(conn)
	name, ok := checkAuth(conn)
	if !ok {
		return
	}

	sidBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, sidBuf); err != nil {
		log.Printf("glue: read session id: %v", err)
		return
	}
	endHandshake(conn)
	sid := hex.EncodeToString(sidBuf)
	transport.SetNotSentLowat(conn, glueNotSentLowat)

	writer := sched.NewPathWriter(conn, gluePathDepth, glueStaleAfter)
	sess, nPaths, ok := attachGluePath(sid, name, conn, writer)
	if !ok {
		writer.Close()
		return
	}
	log.Printf("glue path connected: %s (session %s, client %q, %d path(s) now)", conn.RemoteAddr(), sid, name, nPaths)

	defer func() {
		sess.detachPath(conn)
		writer.Close()
		if d := writer.Drops(); d > 0 {
			log.Printf("glue path %s: %d reply frame(s) dropped while this path was backed up (the other paths carried them)", conn.RemoteAddr(), d)
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(glueReadTimeout))
		f, err := frame.ReadFrame(conn)
		if err != nil {
			log.Printf("glue: path closed (session %s): %v", sid, err)
			return
		}

		// path ping: send it back on this path only, no dedup
		if glue.IsPathPing(f.Payload) {
			writer.Send(f.Marshal())
			continue
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

		if ok, reason := destinations.Allowed(dst); !ok {
			log.Printf("glue: refusing to relay flow %d (session %s): %s", flowID, sid, reason)
			continue
		}
		if ok, reason := glue.DestinationAllowed(dst, dstPort); !ok {
			log.Printf("glue: refusing to relay flow %d (session %s): %s", flowID, sid, reason)
			continue
		}

		udpConn, err := sess.flow(sid, flowID, dst, dstPort)
		if errors.Is(err, errTooManyFlows) {
			continue // already logged
		}
		if err != nil {
			log.Printf("glue: dial UDP for flow %d: %v", flowID, withoutAddr(err))
			continue
		}
		if _, err := udpConn.Write(payload); err != nil {
			log.Printf("glue: write to UDP target for flow %d: %v", flowID, withoutAddr(err))
		}
	}
}

// withoutAddr strips the "dial udp 1.2.3.4:27015:" part net errors carry.
func withoutAddr(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err
	}
	return err
}
