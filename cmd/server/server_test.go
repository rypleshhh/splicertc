package main

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"tcp-dormtun/internal/config"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/sched"
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
	if _, err := claimVPN(a); err != nil {
		t.Fatalf("first client was refused: %v", err)
	}
	a2 := &vpnPeer{name: "alice"}
	if old, err := claimVPN(a2); err != nil || old != a {
		t.Fatal("reconnect of the same client must replace the old connection")
	}
	if _, err := claimVPN(&vpnPeer{name: "bob"}); err == nil {
		t.Fatal("another client kicked the current one")
	}
	if currentVPN != a2 {
		t.Fatal("current client changed")
	}
}

// After a TUN error the current client is disconnected and new ones
// are refused.
func TestStopVPNRefusesClients(t *testing.T) {
	defer func() {
		vpnMu.Lock()
		currentVPN, vpnStopped = nil, false
		vpnMu.Unlock()
	}()
	server, client := net.Pipe()
	defer client.Close()
	if _, err := claimVPN(&vpnPeer{name: "alice", conn: server}); err != nil {
		t.Fatal(err)
	}

	stopVPN(errors.New("test"))

	if _, err := client.Write([]byte{1}); err == nil {
		t.Fatal("the current client was not disconnected")
	}
	if _, err := claimVPN(&vpnPeer{name: "alice"}); !errors.Is(err, errVPNStopped) {
		t.Fatalf("expected errVPNStopped, got %v", err)
	}
}

func TestWithVirtioHdrReusesBuffer(t *testing.T) {
	buf := withVirtioHdr(nil, []byte{1, 2, 3, 4})
	buf[0] = 0xff // the TUN may write an offload header there
	again := withVirtioHdr(buf, []byte{5, 6})
	if &again[0] != &buf[0] {
		t.Fatal("a big enough buffer was not reused")
	}
	want := append(make([]byte, virtioHdrLen), 5, 6)
	if !bytes.Equal(again, want) {
		t.Fatalf("got %v, want %v", again, want)
	}
}

// writeLoop sends several queued frames with one Write; the client
// still reads them as separate frames.
func TestVPNWriteLoopBatches(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	p := &vpnPeer{conn: server, q: sched.New(sched.Config{})}
	for i := 0; i < 3; i++ {
		p.q.Enqueue(keepaliveFlow, frame.New(uint32(i), []byte{byte(i)}).Marshal())
	}
	go p.writeLoop()
	defer p.q.Close()

	for i := 0; i < 3; i++ {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		f, err := frame.ReadFrame(client)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if f.Seq != uint32(i) || !bytes.Equal(f.Payload, []byte{byte(i)}) {
			t.Fatalf("frame %d: got seq %d payload %v", i, f.Seq, f.Payload)
		}
	}
}

func TestParseVPNSubnet(t *testing.T) {
	tests := []struct {
		cidr    string
		wantErr bool
		client  string
	}{
		{"10.66.0.0/24", false, "10.66.0.2"},
		{"10.66.0.4/30", false, "10.66.0.6"},
		{"10.0.0.0/8", false, "10.0.0.2"},
		{"10.66.0.5/24", true, ""}, // host bits set
		{"10.66.0.0/31", true, ""},
		{"10.66.0.0/32", true, ""},
		{"10.0.0.0/7", true, ""},
		{"fd00::/64", true, ""},
		{"nonsense", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			n, err := parseVPNSubnet(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && n.clientIP.String() != tt.client {
				t.Fatalf("client IP %s, want %s", n.clientIP, tt.client)
			}
		})
	}
}

func TestParseIPList(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"203.0.113.5", 1, false},
		{" 203.0.113.5 , 2001:db8::1 ,", 2, false},
		{"203.0.113.5,example.com", 0, true},
		{"203.0.113.0/24", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ips, err := parseIPList(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(ips) != tt.want {
				t.Fatalf("got %d IPs, want %d", len(ips), tt.want)
			}
		})
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

func TestCheckTarget(t *testing.T) {
	tests := []struct {
		addr    string
		allowed bool
	}{
		{"203.0.113.10:443", true},
		{"203.0.113.10:25", false},
		{"[2001:db8::1]:25", false},
		{"203.0.113.10:587", true},
		{"127.0.0.1:443", false},
		{"10.1.2.3:443", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			err := checkTarget(tt.addr)
			if (err == nil) != tt.allowed {
				t.Fatalf("checkTarget(%s) = %v, allowed want %v", tt.addr, err, tt.allowed)
			}
			if err != nil && proto.DialStatus(err) != proto.StatusNotAllowed {
				t.Fatalf("status %#x, want StatusNotAllowed", proto.DialStatus(err))
			}
		})
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

// config.Load rejects unknown fields, so the example must match Config.
func TestExampleConfigLoads(t *testing.T) {
	var cfg Config
	found, err := config.Load("../../server-config.example.json", &cfg)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if cfg.DropAddr != channelOff {
		t.Fatalf("drop_addr = %q, the debug channel should be off in the example", cfg.DropAddr)
	}
}
