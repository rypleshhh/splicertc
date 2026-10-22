package proto

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTargetRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTarget(&buf, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTarget(&buf)
	if err != nil || got != "example.com:443" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestWriteTargetTooLong(t *testing.T) {
	if err := WriteTarget(io.Discard, strings.Repeat("a", maxTarget+1)); err == nil {
		t.Fatal("a target longer than the 16 bit length was accepted")
	}
}

func TestDialStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()
	_, refused := net.Dial("tcp", closedAddr)

	tests := []struct {
		name string
		err  error
		want byte
	}{
		{"ok", nil, StatusOK},
		{"policy", &net.OpError{Op: "dial", Err: ErrNotAllowed}, StatusNotAllowed},
		{"refused", refused, StatusRefused},
		{"dns", &net.DNSError{Err: "no such host", Name: "x.invalid"}, StatusHostUnreachable},
		{"other", io.ErrUnexpectedEOF, StatusFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DialStatus(tt.err); got != tt.want {
				t.Fatalf("DialStatus(%v) = %#x, want %#x", tt.err, got, tt.want)
			}
		})
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c, <-accepted
}

// The client half-closes after its request and must still get the answer.
func TestRelayKeepsHalfClosedConnectionOpen(t *testing.T) {
	client, relayClientSide := tcpPair(t)
	relayServerSide, server := tcpPair(t)
	defer client.Close()
	defer server.Close()
	go Relay(relayClientSide, relayServerSide)

	client.Write([]byte("request"))
	client.(*net.TCPConn).CloseWrite()

	// the server reads the request until EOF, then answers
	req, err := io.ReadAll(server)
	if err != nil || string(req) != "request" {
		t.Fatalf("server got %q, %v", req, err)
	}
	server.Write([]byte("answer"))
	server.Close()

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(client)
	if err != nil || string(resp) != "answer" {
		t.Fatalf("client got %q, %v (answer lost after half-close)", resp, err)
	}
}
