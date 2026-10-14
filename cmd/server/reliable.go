package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/proto"
)

// reliable channel: SOCKS5 on the client, every TCP connection is one
// smux stream inside one TLS connection, the server dials the target.

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
			return fmt.Errorf("target %s is not allowed: %s", host, reason)
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

	// targets are not logged on success, the log shouldn't be a browsing history
	outConn, err := targetDialer.Dial("tcp", target)
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
}

// relay copies both ways until one side is done. The caller closes both
// connections, which also stops the other copy.
func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}
