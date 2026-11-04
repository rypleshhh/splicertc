package main

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestStreamLimiter(t *testing.T) {
	l := newStreamLimiter(2, 3)
	steps := []struct {
		key string
		ok  bool
	}{
		{"a", true},
		{"a", true},
		{"a", false}, // лимит ключа
		{"b", true},
		{"c", false}, // общий лимит
	}
	for i, st := range steps {
		if ok, reason := l.acquire(st.key); ok != st.ok {
			t.Fatalf("step %d (%s): ok=%v (%s), want %v", i, st.key, ok, reason, st.ok)
		}
	}
	l.release("a")
	if ok, _ := l.acquire("c"); !ok {
		t.Fatal("released slot was not reused")
	}
	l.release("b")
	l.release("c")
	l.release("a")
	if l.total != 0 || len(l.perKey) != 0 {
		t.Fatalf("leftover counts: total %d, keys %v", l.total, l.perKey)
	}
}

func TestAcceptLoopRefusesOverLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go acceptLoop("test", ln, func(c net.Conn) {
		defer c.Close()
		<-release
	}, make(chan struct{}, 2))

	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	held := []net.Conn{dial(), dial()}
	time.Sleep(50 * time.Millisecond) // оба заняли слоты

	extra := dial()
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("connection over the limit: got %v, want EOF", err)
	}
	for _, c := range held {
		_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err == io.EOF {
			t.Fatal("a connection within the limit was closed")
		}
	}
}

// Stream без target освобождает слот через streamSetupTimeout, а не висит.
func TestHandleStreamSetupDeadline(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	srv, err := smux.Server(a, smuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := smux.Client(b, smuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.OpenStream(); err != nil {
		t.Fatal(err)
	}
	s, err := srv.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	const timeout = 200 * time.Millisecond
	done := make(chan struct{})
	start := time.Now()
	go func() { handleStream(s, timeout); close(done) }()
	select {
	case <-done:
		if d := time.Since(start); d < timeout {
			t.Fatalf("returned after %v, before the deadline", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream without a target was never dropped")
	}
}
