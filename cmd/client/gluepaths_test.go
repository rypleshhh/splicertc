package main

import (
	"bytes"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
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
	g := newGluePaths("", false, nil, nil, func(frame.Frame) {})
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
	g := newGluePaths("", false, nil, nil, func(f frame.Frame) { recv <- f })
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
	g := newGluePaths("", false, nil, nil, func(frame.Frame) {})
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
