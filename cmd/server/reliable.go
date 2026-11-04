package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/proto"
)

// reliable channel: SOCKS5 on the client, every TCP connection is one
// smux stream inside one TLS connection, the server dials the target.

// smux.DefaultConfig has no limit on the number of streams, and every
// stream is an outgoing TCP connection of the server. The limit is per
// key, not per connection: a client can open several connections.
const (
	maxStreamsPerKey  = 256
	maxOutboundTCP    = 2048     // all clients together
	smuxReceiveBuffer = 4 << 20  // bytes for all streams of a session
	smuxStreamBuffer  = 64 << 10 // bytes per stream
	// a stream that doesn't send its target in this time is dropped
	streamSetupTimeout = 10 * time.Second
)

// streamLimiter counts open streams per key and in total.
type streamLimiter struct {
	mu        sync.Mutex
	perKey    map[string]int
	total     int
	maxPerKey int
	maxTotal  int
}

func newStreamLimiter(maxPerKey, maxTotal int) *streamLimiter {
	return &streamLimiter{perKey: make(map[string]int), maxPerKey: maxPerKey, maxTotal: maxTotal}
}

// acquire takes a slot for keyID; reason says which limit is hit.
func (l *streamLimiter) acquire(keyID string) (ok bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perKey[keyID] >= l.maxPerKey {
		return false, fmt.Sprintf("more than %d streams for this key", l.maxPerKey)
	}
	if l.total >= l.maxTotal {
		return false, fmt.Sprintf("more than %d outgoing connections on the server", l.maxTotal)
	}
	l.perKey[keyID]++
	l.total++
	return true, ""
}

func (l *streamLimiter) release(keyID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perKey[keyID]--; l.perKey[keyID] <= 0 {
		delete(l.perKey, keyID)
	}
}

var streams = newStreamLimiter(maxStreamsPerKey, maxOutboundTCP)

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.MaxReceiveBuffer = smuxReceiveBuffer
	c.MaxStreamBuffer = smuxStreamBuffer
	return c
}

// handleConn serves one reliable-channel client.
func handleConn(conn net.Conn) {
	defer conn.Close()
	startHandshake(conn)
	peer, ok := checkAuth(conn)
	if !ok {
		return
	}
	endHandshake(conn)
	log.Printf("client connected: %s (%s)", conn.RemoteAddr(), peer)

	sess, err := smux.Server(conn, smuxConfig())
	if err != nil {
		log.Printf("smux server: %v", err)
		return
	}
	defer sess.Close()

	limitLogged := false
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("session closed: %v", err)
			return
		}
		if ok, reason := streams.acquire(peer.KeyID); !ok {
			if !limitLogged {
				limitLogged = true
				log.Printf("client %s: %s, refusing new streams", peer, reason)
			}
			stream.Write([]byte{0x01}) // "could not connect"
			stream.Close()
			continue
		}
		go func() {
			defer streams.release(peer.KeyID)
			handleStream(stream, streamSetupTimeout)
		}()
	}
}

// SMTP spam sent through the tunnel would get the VPS banned by the
// hoster, so outgoing mail is not relayed.
const smtpPort = "25"

// targetDialer only connects where the egress policy allows: not to the
// server itself (loopback or its own public IP), not to private networks
// and cloud metadata, not to port 25. The check is done on the resolved
// IP right before connect(), so a hostname pointing to 127.0.0.1 doesn't
// get through.
var targetDialer = net.Dialer{
	Timeout: 10 * time.Second,
	Control: func(network, address string, _ syscall.RawConn) error {
		return checkTarget(address)
	},
}

// checkTarget checks a resolved "ip:port". Errors wrap
// proto.ErrNotAllowed, so the client gets "not allowed by ruleset".
func checkTarget(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if port == smtpPort {
		return fmt.Errorf("%w: port 25 (SMTP) is blocked", proto.ErrNotAllowed)
	}
	if ok, reason := destinations.Allowed(net.ParseIP(host)); !ok {
		return fmt.Errorf("%w: %s: %s", proto.ErrNotAllowed, host, reason)
	}
	return nil
}

// handleStream relays one stream; the target must arrive within setupTimeout.
func handleStream(s *smux.Stream, setupTimeout time.Duration) {
	defer s.Close()

	// a stream that never sends its target would hold its slot forever
	_ = s.SetReadDeadline(time.Now().Add(setupTimeout))
	target, err := proto.ReadTarget(s)
	if err != nil {
		log.Printf("stream %d: read target: %v", s.ID(), err)
		return
	}
	_ = s.SetReadDeadline(time.Time{})

	outConn, err := targetDialer.Dial("tcp", target)
	if err != nil {
		// the client gets the SOCKS5 error code; targets are not logged,
		// the log shouldn't be a browsing history
		s.Write([]byte{proto.DialStatus(err)})
		return
	}
	if _, err := s.Write([]byte{proto.StatusOK}); err != nil {
		outConn.Close()
		return
	}
	proto.Relay(s, outConn)
}
