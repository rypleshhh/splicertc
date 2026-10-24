package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/transport"
)

// fakeSmuxServer echoes every stream. Closing the returned conn drops
// the session like a lost connection.
func fakeSmuxServer(t *testing.T) (client *smux.Session, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	srv, err := smux.Server(s, smuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			st, err := srv.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				defer st.Close()
				io.Copy(st, st)
			}()
		}
	}()
	sess, err := smux.Client(c, smuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close(); srv.Close() })
	return sess, s
}

func echoOnce(t *testing.T, s *socksSession) {
	t.Helper()
	st, err := s.openStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer st.Close()
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

// A lost session is dialed again by the next app connection.
func TestSocksSessionRedials(t *testing.T) {
	var dials atomic.Int32
	var servers []net.Conn
	s := &socksSession{dial: func() (*smux.Session, error) {
		dials.Add(1)
		sess, server := fakeSmuxServer(t)
		servers = append(servers, server)
		return sess, nil
	}}
	echoOnce(t, s)
	echoOnce(t, s)
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials for a healthy session", n)
	}

	servers[0].Close()
	deadline := time.Now().Add(3 * time.Second)
	for !s.sess.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	echoOnce(t, s)
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials after the session was lost, want 2", n)
	}
}

// While the server is down, connections fail fast without a dial each.
func TestSocksSessionBackoff(t *testing.T) {
	var dials atomic.Int32
	s := &socksSession{dial: func() (*smux.Session, error) {
		dials.Add(1)
		return nil, errors.New("connection refused")
	}}
	for i := 0; i < 5; i++ {
		if _, err := s.openStream(); err == nil {
			t.Fatal("expected an error")
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials within the backoff, want 1", n)
	}
}

// A wrong key or certificate stops the client: no more dials (they'd
// get the IP banned), and the error goes to onFatal.
func TestSocksSessionPermanentError(t *testing.T) {
	cases := []error{auth.ErrRejected, transport.ErrPinMismatch}
	for _, permErr := range cases {
		t.Run(permErr.Error(), func(t *testing.T) {
			var dials atomic.Int32
			var fatal error
			s := &socksSession{
				dial: func() (*smux.Session, error) {
					dials.Add(1)
					return nil, fmt.Errorf("auth: %w", permErr)
				},
				onFatal: func(err error) { fatal = err },
			}
			for i := 0; i < 3; i++ {
				s.nextDial = time.Time{} // no backoff in the way
				if _, err := s.openStream(); !errors.Is(err, permErr) {
					t.Fatalf("got %v", err)
				}
			}
			if n := dials.Load(); n != 1 {
				t.Fatalf("%d dials after a permanent error, want 1", n)
			}
			if !errors.Is(fatal, permErr) {
				t.Fatalf("onFatal got %v", fatal)
			}
		})
	}
}
