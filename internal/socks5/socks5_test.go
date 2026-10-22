package socks5

import (
	"io"
	"net"
	"testing"
)

func TestReadRequestIPv6Target(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		req := []byte{version5, cmdConnect, 0, atypIPv6}
		req = append(req, net.ParseIP("2001:db8::1")...)
		req = append(req, 0x01, 0xbb) // 443
		b.Write(req)
	}()
	got, err := ReadRequest(a)
	if err != nil {
		t.Fatal(err)
	}
	if got != "[2001:db8::1]:443" {
		t.Fatalf("got %q", got)
	}
}

// A client that doesn't offer "no auth" gets 0xFF, not a silent yes.
func TestHandshakeRejectsWithoutNoAuth(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go b.Write([]byte{version5, 1, 0x02}) // only username/password
	errCh := make(chan error, 1)
	go func() { errCh <- Handshake(a) }()
	reply := make([]byte, 2)
	if _, err := io.ReadFull(b, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != methodNoAcceptable {
		t.Fatalf("reply method %#x, want 0xFF", reply[1])
	}
	if err := <-errCh; err == nil {
		t.Fatal("Handshake succeeded without the no-auth method")
	}
}
