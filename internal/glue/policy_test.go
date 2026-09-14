package glue

import (
	"net"
	"testing"
)

func TestLegitimateGameServerAllowed(t *testing.T) {
	ok, reason := DestinationAllowed(net.ParseIP("203.0.113.50"), 27015)
	if !ok {
		t.Errorf("expected a normal public unicast destination to be allowed, got reason=%q", reason)
	}
}

func TestLoopbackBlocked(t *testing.T) {
	ok, _ := DestinationAllowed(net.ParseIP("127.0.0.1"), 9999)
	if ok {
		t.Error("expected loopback destination to be blocked")
	}
}

func TestMulticastBlocked(t *testing.T) {
	ok, _ := DestinationAllowed(net.ParseIP("224.0.0.251"), 5353)
	if ok {
		t.Error("expected multicast destination to be blocked")
	}
}

func TestAmplificationPortsBlocked(t *testing.T) {
	for _, port := range []uint16{53, 123, 11211, 1900} {
		ok, reason := DestinationAllowed(net.ParseIP("203.0.113.50"), port)
		if ok {
			t.Errorf("expected port %d to be blocked, it wasn't", port)
		}
		if reason == "" {
			t.Errorf("expected a reason for blocking port %d", port)
		}
	}
}

func TestLinkLocalBlocked(t *testing.T) {
	ok, _ := DestinationAllowed(net.ParseIP("169.254.1.1"), 9999)
	if ok {
		t.Error("expected link-local destination to be blocked")
	}
}
