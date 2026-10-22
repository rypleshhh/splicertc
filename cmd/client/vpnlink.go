package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/transport"
)

// The client sends an empty frame every vpnKeepaliveInterval and the
// server sends it back. No frames at all for vpnReadTimeout means the
// connection is dead even if TCP didn't notice yet (the dorm network
// sometimes just stops forwarding without a RST).
const (
	vpnKeepaliveInterval = 2 * time.Second
	vpnReadTimeout       = 7 * time.Second
	vpnWriteTimeout      = 10 * time.Second
)

// vpnLink is the vpn connection that reconnects by itself. Packets
// written while it's down are dropped, TCP inside the tunnel resends them.
type vpnLink struct {
	addr        string
	dial        func() (net.Conn, error)
	onPacket    func([]byte)
	readTimeout time.Duration

	mu     sync.Mutex
	conn   net.Conn // nil while reconnecting
	closed bool
}

// isPermanentDialError is true for errors that won't go away by
// reconnecting: wrong key or a different server certificate.
func isPermanentDialError(err error) bool {
	return errors.Is(err, auth.ErrRejected) || errors.Is(err, transport.ErrPinMismatch)
}

func dialVPN(srv endpoint, key []byte) (net.Conn, error) {
	c, err := transport.Dial(srv.addr, srv.dc)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(transport.DialTimeout))
	if err := auth.ClientHandshake(c, key); err != nil {
		c.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// run serves conn and reconnects when it's lost. It returns only on a
// permanent dial error or after close.
func (l *vpnLink) run(conn net.Conn) error {
	for {
		err := l.serve(conn)
		if l.isClosed() {
			return nil
		}
		log.Printf("vpn: connection lost (%v), reconnecting", err)

		backoff := redialMin
		for {
			time.Sleep(backoff)
			if l.isClosed() {
				return nil
			}
			conn, err = l.dial()
			if err == nil {
				break
			}
			// retrying won't help here, and with a wrong key it would
			// only get this IP banned
			if isPermanentDialError(err) {
				return fmt.Errorf("vpn: reconnect: %w", err)
			}
			log.Printf("vpn: reconnect failed: %v (retry in %v)", err, min(backoff*2, redialMax))
			backoff = min(backoff*2, redialMax)
		}
		// the tray looks for this line
		log.Printf("connected to vpn channel %s", l.addr)
	}
}

// close drops the connection and stops run from reconnecting.
func (l *vpnLink) close() {
	l.mu.Lock()
	l.closed = true
	conn := l.conn
	l.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (l *vpnLink) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// serve reads from conn until it fails.
func (l *vpnLink) serve(conn net.Conn) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	l.conn = conn
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		if l.conn == conn {
			l.conn = nil
		}
		l.mu.Unlock()
		conn.Close()
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(l.readTimeout))
		f, err := frame.ReadFrame(conn)
		if err != nil {
			return err
		}
		if len(f.Payload) == 0 {
			continue // keepalive reply
		}
		l.onPacket(f.Payload)
	}
}

// write sends frames, several of them in one write if the caller
// batched them. Only one goroutine calls it, so writes don't mix.
func (l *vpnLink) write(wire []byte) {
	l.mu.Lock()
	conn := l.conn
	l.mu.Unlock()
	if conn == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(vpnWriteTimeout))
	if _, err := conn.Write(wire); err != nil {
		conn.Close() // serve() sees the error and reconnects
	}
}
