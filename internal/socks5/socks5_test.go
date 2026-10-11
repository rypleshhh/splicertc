package socks5

import (
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
