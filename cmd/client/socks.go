package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/socks5"
	"tcp-dormtun/internal/transport"
)

// socks5 mode: a local SOCKS5 proxy, every TCP connection becomes one
// smux stream inside a single TLS connection to the server.

// smux limits, the same as on the server. The default has no limit on
// the receive buffer.
const (
	smuxReceiveBuffer = 4 << 20  // bytes for all streams of a session
	smuxStreamBuffer  = 64 << 10 // bytes per stream
)

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.MaxReceiveBuffer = smuxReceiveBuffer
	c.MaxStreamBuffer = smuxStreamBuffer
	return c
}

// runSocksMode returns only on an error: the first connect failed, the
// listener couldn't start, or a reconnect failed permanently.
func runSocksMode(srv endpoint, listenAddr string, key []byte) error {
	stop := make(chan error, 1)
	s := &socksSession{
		dial: func() (*smux.Session, error) { return dialSocks(srv, key) },
		onFatal: func(err error) {
			select {
			case stop <- err:
			default:
			}
		},
	}
	sess, err := s.dial()
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	s.sess = sess
	defer s.close()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer ln.Close()
	log.Printf("SOCKS5 proxy listening on %s", listenAddr)

	go func() {
		for {
			appConn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("accept: %v", err)
				continue
			}
			go handleApp(appConn, s)
		}
	}()
	return <-stop
}

func dialSocks(srv endpoint, key []byte) (*smux.Session, error) {
	conn, err := transport.Dial(srv.addr, srv.dc)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(transport.DialTimeout))
	if err := auth.ClientHandshake(conn, key); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	sess, err := smux.Client(conn, smuxConfig())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smux client: %w", err)
	}
	log.Printf("connected to tunnel server %s", srv.addr)
	return sess, nil
}

// socksSession is the smux session to the server. When it's lost, the
// next app connection dials a new one. While the server can't be
// reached, app connections fail right away instead of waiting.
type socksSession struct {
	dial func() (*smux.Session, error)
	// onFatal gets errors that reconnecting won't fix (wrong key or
	// certificate). After that no more dials are made.
	onFatal func(error)

	mu       sync.Mutex
	sess     *smux.Session // nil after it was lost
	backoff  time.Duration
	nextDial time.Time
	fatal    error
}

func (s *socksSession) openStream() (*smux.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil && !s.sess.IsClosed() {
		stream, err := s.sess.OpenStream()
		if err == nil {
			return stream, nil
		}
	}
	if s.sess != nil {
		log.Printf("socks: connection to the server lost, reconnecting")
		s.sess.Close()
		s.sess = nil
	}

	if s.fatal != nil {
		return nil, s.fatal
	}
	if wait := time.Until(s.nextDial); wait > 0 {
		return nil, fmt.Errorf("server unreachable, next try in %v", wait.Round(time.Millisecond))
	}
	sess, err := s.dial()
	if err != nil {
		// a wrong key would only get this IP banned if retried
		if isPermanentDialError(err) {
			s.fatal = fmt.Errorf("socks: reconnect: %w", err)
			if s.onFatal != nil {
				s.onFatal(s.fatal)
			}
			return nil, s.fatal
		}
		s.backoff = min(max(2*s.backoff, redialMin), redialMax)
		s.nextDial = time.Now().Add(s.backoff)
		return nil, err
	}
	s.backoff = 0
	s.sess = sess
	return sess.OpenStream()
}

func (s *socksSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil {
		s.sess.Close()
	}
}

func handleApp(appConn net.Conn, s *socksSession) {
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

	stream, err := s.openStream()
	if err != nil {
		log.Printf("open stream: %v", err)
		socks5.WriteReply(appConn, proto.StatusFailure)
		return
	}
	defer stream.Close()

	if err := proto.WriteTarget(stream, target); err != nil {
		log.Printf("send target: %v", err)
		socks5.WriteReply(appConn, proto.StatusFailure)
		return
	}

	// the server answers with a SOCKS5 reply code
	status := make([]byte, 1)
	if _, err := io.ReadFull(stream, status); err != nil {
		socks5.WriteReply(appConn, proto.StatusFailure)
		return
	}
	if err := socks5.WriteReply(appConn, status[0]); err != nil || status[0] != proto.StatusOK {
		return
	}
	proto.Relay(appConn, stream)
}
