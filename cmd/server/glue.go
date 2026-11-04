package main

import (
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/sched"
	"tcp-dormtun/internal/transport"
)

// glueSession is shared by all paths with the same session ID.
// udpFlows are the UDP sockets to game servers, paths are the client
// connections replies are sent to.
type glueSession struct {
	// another key can't join, even with the same name
	owner auth.Peer
	// random, sent to every path that joins: the client resets its reply
	// dedup when it sees a new one, replySeq of a new session starts at 0
	epoch uint64

	mu       sync.Mutex
	recv     *frame.Receiver
	udpFlows map[uint16]*udpFlow
	// nil writer: the path is accepted but its accept message is not
	// written yet, broadcasts skip it
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

// reserveFlow takes one slot of maxTotalFlows. Add-then-check, so two
// sessions can't both pass a check at the last free slot.
func reserveFlow() bool {
	if totalFlows.Add(1) > maxTotalFlows {
		totalFlows.Add(-1)
		return false
	}
	return true
}

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

// attachGluePath finds or creates the session and reserves a path slot
// for conn; setWriter turns it on once the accept message is written.
// Both happen under glueSessions.mu so the janitor can't delete the
// session in between. status is glue.StatusOK or the reason to refuse.
func attachGluePath(id string, owner auth.Peer, conn net.Conn) (s *glueSession, paths int, status byte) {
	glueSessions.mu.Lock()
	defer glueSessions.mu.Unlock()
	s, exists := glueSessions.m[id]
	if !exists {
		if !makeRoomForSession(owner.KeyID) {
			log.Printf("glue: %s already has %d active sessions, rejecting %s", owner, maxSessionsPerClient, conn.RemoteAddr())
			return nil, 0, glue.StatusBusy
		}
		if len(glueSessions.m) >= maxGlueSessions {
			log.Printf("glue: too many sessions (%d), rejecting %s", maxGlueSessions, conn.RemoteAddr())
			return nil, 0, glue.StatusBusy
		}
		s = &glueSession{
			owner:    owner,
			epoch:    newEpoch(),
			recv:     frame.NewReceiver(150 * time.Millisecond),
			udpFlows: make(map[uint16]*udpFlow),
			paths:    make(map[net.Conn]*sched.PathWriter),
		}
		glueSessions.m[id] = s
	}
	if s.owner.KeyID != owner.KeyID {
		log.Printf("glue: session %s belongs to %s, rejecting %s from %s", id, s.owner, owner, conn.RemoteAddr())
		return nil, 0, glue.StatusRefused
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.paths) >= maxPathsPerSession {
		log.Printf("glue: session %s already has %d paths, rejecting %s", id, maxPathsPerSession, conn.RemoteAddr())
		return nil, 0, glue.StatusBusy
	}
	s.paths[conn] = nil
	s.emptySince = time.Time{}
	return s, len(s.paths), glue.StatusOK
}

// setWriter starts sending replies to a path reserved by attachGluePath.
func (s *glueSession) setWriter(conn net.Conn, w *sched.PathWriter) {
	s.mu.Lock()
	if _, ok := s.paths[conn]; ok {
		s.paths[conn] = w
	}
	s.mu.Unlock()
}

// newEpoch is never 0: the client starts with 0 as "no session yet".
func newEpoch() uint64 {
	for {
		if e := rand.Uint64(); e != 0 {
			return e
		}
	}
}

// makeRoomForSession checks the per-client session limit. Sessions of a
// restarted client linger for glueSessionIdle without paths; those are
// removed first to make room. Called with glueSessions.mu held.
func makeRoomForSession(keyID string) bool {
	var count int
	var oldestID string
	var oldest *glueSession
	var oldestSince time.Time
	for id, s := range glueSessions.m {
		if s.owner.KeyID != keyID {
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
// The map entry and the quota slot go away only if flowID still points
// to f: a reader of a rebound flow must not remove the new socket, and
// the slot is freed once. Called with s.mu held.
func (s *glueSession) closeFlowLocked(flowID uint16, f *udpFlow) {
	f.conn.Close()
	if s.udpFlows[flowID] != f {
		return
	}
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
	if len(s.udpFlows) >= maxFlowsPerSession || !reserveFlow() {
		if !s.flowLimitLogged {
			s.flowLimitLogged = true
			log.Printf("glue: session %s hit the flow limit (%d per session, %d in total), new flows are dropped", sid, maxFlowsPerSession, maxTotalFlows)
		}
		return nil, errTooManyFlows
	}

	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		totalFlows.Add(-1)
		return nil, err
	}
	f := &udpFlow{conn: uc, dst: key, lastSeen: now}
	s.udpFlows[flowID] = f
	// no address in the log: it shouldn't be a list of the client's servers
	log.Printf("glue: new flow %d (session %s)", flowID, sid)

	go s.readFlow(sid, flowID, f)
	return uc, nil
}

// readFlow forwards replies of one flow until its socket fails or is
// closed. A failed flow is removed, so the next packet of the client
// opens a new socket instead of writing into one nobody reads.
func (s *glueSession) readFlow(sid string, flowID uint16, f *udpFlow) {
	buf := make([]byte, 65535)
	for {
		n, err := f.conn.Read(buf)
		if errors.Is(err, syscall.ECONNREFUSED) {
			// ICMP port unreachable on a connected socket (Linux): the game
			// server is restarting, the socket itself is fine. Keeping it
			// keeps the source port the server knows the client by.
			continue
		}
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("glue: flow %d (session %s) read failed, closing it: %v", flowID, sid, withoutAddr(err))
			}
			s.mu.Lock()
			s.closeFlowLocked(flowID, f)
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		f.lastSeen = time.Now()
		s.mu.Unlock()
		s.broadcastReply(flowID, buf[:n])
	}
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
		if w != nil {
			writers = append(writers, w)
		}
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
	peer, ok := checkAuth(conn)
	if !ok {
		return
	}

	hello := make([]byte, glue.HelloSize)
	if _, err := io.ReadFull(conn, hello); err != nil {
		log.Printf("glue: read hello: %v", err)
		return
	}
	version, sidBuf := glue.DecodeHello(hello)
	if version != glue.ProtocolVersion {
		log.Printf("glue: %s speaks protocol version %d, this server %d", conn.RemoteAddr(), version, glue.ProtocolVersion)
		_, _ = conn.Write(glue.EncodeAccept(glue.StatusUnsupported, 0))
		return
	}
	sid := hex.EncodeToString(sidBuf)

	sess, nPaths, status := attachGluePath(sid, peer, conn)
	if status != glue.StatusOK {
		_, _ = conn.Write(glue.EncodeAccept(status, 0))
		return
	}
	defer sess.detachPath(conn)
	// written before the writer exists, so no reply can get in front of it
	if _, err := conn.Write(glue.EncodeAccept(glue.StatusOK, sess.epoch)); err != nil {
		log.Printf("glue: send accept: %v", err)
		return
	}
	endHandshake(conn)
	transport.SetNotSentLowat(conn, glueNotSentLowat)

	writer := sched.NewPathWriter(conn, gluePathDepth, glueStaleAfter)
	sess.setWriter(conn, writer)
	log.Printf("glue path connected: %s (session %s, client %s, %d path(s) now)", conn.RemoteAddr(), sid, peer, nPaths)

	defer func() {
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
