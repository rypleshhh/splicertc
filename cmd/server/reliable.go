package main

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/proto"
)

// reliable channel: SOCKS5 on the client, every TCP connection is one
// smux stream inside one TLS connection, the server dials the target.

// Limits per client connection. smux.DefaultConfig has no limit on the
// number of streams, and every stream is an outgoing TCP connection of
// the server, so one client could use up all file descriptors.
const (
	maxStreamsPerSession = 256
	smuxReceiveBuffer    = 4 << 20  // bytes for all streams of a session
	smuxStreamBuffer     = 64 << 10 // bytes per stream
)

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
	name, ok := checkAuth(conn)
	if !ok {
		return
	}
	endHandshake(conn)
	log.Printf("client connected: %s (%q)", conn.RemoteAddr(), name)

	sess, err := smux.Server(conn, smuxConfig())
	if err != nil {
		log.Printf("smux server: %v", err)
		return
	}
	defer sess.Close()

	slots := make(chan struct{}, maxStreamsPerSession)
	limitLogged := false
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("session closed: %v", err)
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			if !limitLogged {
				limitLogged = true
				log.Printf("client %q: more than %d streams at once, refusing new ones", name, maxStreamsPerSession)
			}
			stream.Write([]byte{0x01}) // "could not connect"
			stream.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			handleStream(stream)
		}()
	}
}

// targetDialer only connects where the egress policy allows: not to the
// server itself (loopback or its own public IP), not to private networks
// and cloud metadata. The check is done on the resolved IP right before
// connect(), so a hostname pointing to 127.0.0.1 doesn't get through.
var targetDialer = net.Dialer{
	Timeout: 10 * time.Second,
	Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ok, reason := destinations.Allowed(net.ParseIP(host)); !ok {
			return fmt.Errorf("%w: %s: %s", proto.ErrNotAllowed, host, reason)
		}
		return nil
	},
}

func handleStream(s *smux.Stream) {
	defer s.Close()

	target, err := proto.ReadTarget(s)
	if err != nil {
		log.Printf("stream %d: read target: %v", s.ID(), err)
		return
	}

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
