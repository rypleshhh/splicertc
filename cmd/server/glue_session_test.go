package main

import (
	"net"
	"testing"
	"time"

	"tcp-dormtun/internal/sched"
)

func udpListener(t *testing.T) *net.UDPConn {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func testSession(t *testing.T, id string) (*glueSession, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { b.Close() })
	w := sched.NewPathWriter(a, 4, 0)
	t.Cleanup(w.Close)
	s, n, ok := attachGluePath(id, "me", a, w)
	if !ok || n != 1 {
		t.Fatalf("expected 1 path, got %d", n)
	}
	t.Cleanup(func() {
		glueSessions.mu.Lock()
		delete(glueSessions.m, id)
		glueSessions.mu.Unlock()
	})
	return s, a
}

func TestGlueFlowReusedAndRebound(t *testing.T) {
	s, _ := testSession(t, "rebind")
	a, b := udpListener(t), udpListener(t)
	lo := net.IPv4(127, 0, 0, 1)
	portA := uint16(a.LocalAddr().(*net.UDPAddr).Port)
	portB := uint16(b.LocalAddr().(*net.UDPAddr).Port)

	c1, err := s.flow("rebind", 7, lo, portA)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := s.flow("rebind", 7, lo, portA)
	if c1 != c2 {
		t.Fatal("same flow and destination must reuse the socket")
	}

	c3, err := s.flow("rebind", 7, lo, portB)
	if err != nil {
		t.Fatal(err)
	}
	if c3 == c1 {
		t.Fatal("flow moved to another destination but kept the old socket")
	}
	if _, err := c1.Write([]byte("x")); err == nil {
		t.Fatal("old socket should be closed after rebinding")
	}
	if _, err := c3.Write([]byte("x")); err != nil {
		t.Fatalf("new socket: %v", err)
	}
	buf := make([]byte, 8)
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := b.ReadFromUDP(buf); err != nil {
		t.Fatalf("packet did not reach the new destination: %v", err)
	}
}

func TestCleanupRemovesIdleFlowsAndSessions(t *testing.T) {
	s, conn := testSession(t, "cleanup")
	l := udpListener(t)
	port := uint16(l.LocalAddr().(*net.UDPAddr).Port)
	if _, err := s.flow("cleanup", 1, net.IPv4(127, 0, 0, 1), port); err != nil {
		t.Fatal(err)
	}

	cleanupGlue(time.Now())
	s.mu.Lock()
	n := len(s.udpFlows)
	s.mu.Unlock()
	if n != 1 {
		t.Fatal("active flow was removed")
	}

	later := time.Now().Add(glueFlowIdle + time.Second)
	cleanupGlue(later)
	s.mu.Lock()
	n = len(s.udpFlows)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("idle flow was not removed")
	}

	// session with a connected path stays
	glueSessions.mu.Lock()
	_, ok := glueSessions.m["cleanup"]
	glueSessions.mu.Unlock()
	if !ok {
		t.Fatal("session with a path was removed")
	}

	s.detachPath(conn)
	cleanupGlue(time.Now().Add(glueSessionIdle + time.Second))
	glueSessions.mu.Lock()
	_, ok = glueSessions.m["cleanup"]
	glueSessions.mu.Unlock()
	if ok {
		t.Fatal("session without paths was not removed")
	}
}

// Another client must not join (and read replies of) someone else's session.
func TestGlueSessionOwnedByOneClient(t *testing.T) {
	testSession(t, "owned")
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := sched.NewPathWriter(a, 4, 0)
	defer w.Close()
	if _, _, ok := attachGluePath("owned", "stranger", a, w); ok {
		t.Fatal("a different client joined the session")
	}
}

func TestGlueFlowLimit(t *testing.T) {
	s, _ := testSession(t, "limit")
	l := udpListener(t)
	port := uint16(l.LocalAddr().(*net.UDPAddr).Port)
	lo := net.IPv4(127, 0, 0, 1)
	for i := 0; i < maxFlowsPerSession; i++ {
		if _, err := s.flow("limit", uint16(i), lo, port); err != nil {
			t.Fatalf("flow %d: %v", i, err)
		}
	}
	if _, err := s.flow("limit", uint16(maxFlowsPerSession), lo, port); err != errTooManyFlows {
		t.Fatalf("expected errTooManyFlows, got %v", err)
	}
	cleanupGlue(time.Now().Add(glueFlowIdle + time.Second))
}
