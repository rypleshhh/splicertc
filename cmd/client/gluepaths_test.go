package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/transport"
)

// fakeGlueServer serves one path. If echo is false it reads everything
// but never answers path pings, like a path that went dead.
func fakeGlueServer(c net.Conn, echo bool, got chan<- []byte) {
	defer c.Close()
	for {
		f, err := frame.ReadFrame(c)
		if err != nil {
			return
		}
		if glue.IsPathPing(f.Payload) {
			if echo {
				if _, err := c.Write(f.Marshal()); err != nil {
					return
				}
			}
			continue
		}
		if got != nil {
			got <- f.Payload
		}
	}
}

func TestGluePathsRedialDeadPath(t *testing.T) {
	var dials atomic.Int32
	g := newGluePaths(endpoint{}, nil, func(frame.Frame) {}, nil)
	g.dial = func() (net.Conn, error) {
		client, server := net.Pipe()
		// the first connection never answers pings, later ones do
		go fakeGlueServer(server, dials.Add(1) > 1, nil)
		return client, nil
	}
	if err := g.start(1); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for dials.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("dead path was not redialed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// the new path stays up
	time.Sleep(2 * pathDeadAfter)
	if n := dials.Load(); n != 2 {
		t.Fatalf("healthy path was redialed, %d dials", n)
	}
	if g.live() != 1 {
		t.Fatalf("expected 1 live path, got %d", g.live())
	}
}

func TestGluePathsSendAndReceive(t *testing.T) {
	got := make(chan []byte, 16)
	recv := make(chan frame.Frame, 16)
	g := newGluePaths(endpoint{}, nil, func(f frame.Frame) { recv <- f }, nil)
	var servers []net.Conn
	g.dial = func() (net.Conn, error) {
		client, server := net.Pipe()
		servers = append(servers, server)
		go fakeGlueServer(server, true, got)
		return client, nil
	}
	if err := g.start(1); err != nil {
		t.Fatal(err)
	}
	for g.live() == 0 {
		time.Sleep(time.Millisecond)
	}

	g.send(frame.New(1, []byte("hello")).Marshal())
	select {
	case p := <-got:
		if !bytes.Equal(p, []byte("hello")) {
			t.Fatalf("server got %q", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame not delivered to the path")
	}

	// a frame from the server (not a path ping) reaches onFrame
	go servers[0].Write(frame.New(7, glue.EncodeInbound(1, []byte("reply"))).Marshal())
	select {
	case f := <-recv:
		if f.Seq != 7 {
			t.Fatalf("unexpected frame %d", f.Seq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server frame not passed to onFrame")
	}
}

func TestGluePathsStartFailsWhenNothingConnects(t *testing.T) {
	g := newGluePaths(endpoint{}, nil, func(frame.Frame) {}, nil)
	g.dial = func() (net.Conn, error) { return nil, errors.New("refused") }
	if err := g.start(3); err == nil {
		t.Fatal("expected an error when no path can connect")
	}
}

func TestVPNLinkReconnects(t *testing.T) {
	packets := make(chan []byte, 4)
	var servers = make(chan net.Conn, 4)
	l := &vpnLink{
		onPacket:    func(p []byte) { packets <- p },
		readTimeout: time.Second,
		dial: func() (net.Conn, error) {
			client, server := net.Pipe()
			servers <- server
			return client, nil
		},
	}
	first, _ := l.dial()
	go l.run(first)

	// server drops the first connection
	s1 := <-servers
	s1.Close()

	// the link dials again and works
	var s2 net.Conn
	select {
	case s2 = <-servers:
	case <-time.After(3 * time.Second):
		t.Fatal("no reconnect after the connection was lost")
	}
	go s2.Write(frame.New(1, []byte("pkt")).Marshal())
	select {
	case p := <-packets:
		if string(p) != "pkt" {
			t.Fatalf("got %q", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet not delivered after reconnect")
	}

	// a silent connection is dropped after readTimeout
	select {
	case <-servers:
	case <-time.After(3 * time.Second):
		t.Fatal("silent connection was not dropped")
	}
}

// A wrong key stops the path (retrying gets the IP banned) and reports
// to onFatal instead of exiting the process.
func TestGluePathsPermanentErrorStops(t *testing.T) {
	var dials atomic.Int32
	fatal := make(chan error, 4)
	g := newGluePaths(endpoint{}, nil, func(frame.Frame) {}, func(err error) { fatal <- err })
	g.dial = func() (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("auth: %w", auth.ErrRejected)
	}
	if err := g.start(2); !errors.Is(err, auth.ErrRejected) {
		t.Fatalf("start: got %v", err)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-fatal:
			if !strings.Contains(err.Error(), "server rejected the client key") {
				t.Fatalf("onFatal got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("onFatal not called")
		}
	}
	time.Sleep(2 * redialMin)
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials, want one per path", n)
	}
}

// run returns a permanent reconnect error instead of exiting, with the
// text the tray looks for.
func TestVPNLinkPermanentErrorReturns(t *testing.T) {
	var dials atomic.Int32
	l := &vpnLink{
		onPacket:    func([]byte) {},
		readTimeout: time.Second,
		dial: func() (net.Conn, error) {
			dials.Add(1)
			return nil, transport.ErrPinMismatch
		},
	}
	client, server := net.Pipe()
	server.Close()
	done := make(chan error, 1)
	go func() { done <- l.run(client) }()
	select {
	case err := <-done:
		if !errors.Is(err, transport.ErrPinMismatch) ||
			!strings.Contains(err.Error(), "server certificate does not match pinned fingerprint") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return on a permanent error")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials after a permanent error, want 1", n)
	}
}

// close stops run without reconnecting.
func TestVPNLinkClose(t *testing.T) {
	var dials atomic.Int32
	l := &vpnLink{
		onPacket:    func([]byte) {},
		readTimeout: time.Minute,
		dial: func() (net.Conn, error) {
			dials.Add(1)
			c, _ := net.Pipe()
			return c, nil
		},
	}
	client, _ := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- l.run(client) }()
	for {
		l.mu.Lock()
		up := l.conn != nil
		l.mu.Unlock()
		if up {
			break
		}
		time.Sleep(time.Millisecond)
	}
	l.close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after close")
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("%d dials after close", n)
	}
}
