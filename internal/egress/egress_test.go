package egress

import (
	"net"
	"testing"
)

func TestAllowed(t *testing.T) {
	p := &Policy{own: map[string]bool{"203.0.113.7": true}}
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"1.1.1.1", true},
		{"2606:4700::1111", true},
		{"203.0.113.7", false}, // the server's own public IP
		{"127.0.0.1", false},
		{"::1", false},
		{"169.254.169.254", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
		{"10.0.0.5", false},
		{"172.17.0.2", false}, // docker
		{"192.168.1.1", false},
		{"100.64.0.1", false}, // CGNAT
		{"fd00::1", false},
	} {
		got, reason := p.Allowed(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("Allowed(%s) = %v (%s), want %v", c.ip, got, reason, c.want)
		}
	}
}

func TestAllowPrivate(t *testing.T) {
	p := &Policy{AllowPrivate: true, own: map[string]bool{"10.0.0.9": true}}
	if ok, _ := p.Allowed(net.ParseIP("10.0.0.5")); !ok {
		t.Fatal("private address refused with AllowPrivate")
	}
	// own address and loopback stay blocked
	if ok, _ := p.Allowed(net.ParseIP("10.0.0.9")); ok {
		t.Fatal("own address allowed")
	}
	if ok, _ := p.Allowed(net.ParseIP("127.0.0.1")); ok {
		t.Fatal("loopback allowed")
	}
}

// New must find at least the loopback address of the test machine.
func TestNewLoadsOwnAddresses(t *testing.T) {
	p := New(false)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.own["127.0.0.1"] && !p.own["::1"] {
		t.Fatalf("no loopback in own addresses: %v", p.own)
	}
}
