package main

import (
	"net"
	"testing"
	"time"
)

func TestFromClientRejectsSpoofedSource(t *testing.T) {
	client := net.IPv4(10, 66, 0, 2)
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[12:16], []byte{10, 66, 0, 2})
	if !fromClient(pkt, client) {
		t.Fatal("packet from the client address was rejected")
	}
	copy(pkt[12:16], []byte{8, 8, 8, 8})
	if fromClient(pkt, client) {
		t.Fatal("packet with a spoofed source was accepted")
	}
	if fromClient([]byte{0x60, 0, 0}, client) {
		t.Fatal("short / IPv6 packet was accepted")
	}
}

func TestClaimVPN(t *testing.T) {
	defer func() { currentVPN = nil }()
	a := &vpnPeer{name: "alice"}
	if _, ok := claimVPN(a); !ok {
		t.Fatal("first client was refused")
	}
	a2 := &vpnPeer{name: "alice"}
	if old, ok := claimVPN(a2); !ok || old != a {
		t.Fatal("reconnect of the same client must replace the old connection")
	}
	if _, ok := claimVPN(&vpnPeer{name: "bob"}); ok {
		t.Fatal("another client kicked the current one")
	}
	if currentVPN != a2 {
		t.Fatal("current client changed")
	}
}

func TestTCPTargetAllowed(t *testing.T) {
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"1.1.1.1", true},
		{"10.0.0.5", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"169.254.169.254", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
	} {
		if got := tcpTargetAllowed(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("tcpTargetAllowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// The resolved address is checked, so "localhost" doesn't get through.
func TestTargetDialerRefusesLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if c, err := targetDialer.Dial("tcp", "localhost:"+port); err == nil {
		c.Close()
		t.Fatal("dialed the server's own loopback")
	}
}

func TestAuthFailuresAreForgotten(t *testing.T) {
	recordAuthFailure("203.0.113.9")
	cleanupAuthFailures(time.Now().Add(authFailureMemory + time.Minute))
	authFailures.mu.Lock()
	_, left := authFailures.count["203.0.113.9"]
	authFailures.mu.Unlock()
	if left {
		t.Fatal("old failure was not forgotten")
	}
}
