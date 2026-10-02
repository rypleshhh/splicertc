package pktfilter

import "testing"

// buildIPv4UDP makes a test packet, checksum is not set.
func buildIPv4UDP(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 28) // 20 IP + 8 UDP, no payload
	pkt[0] = 0x45           // IPv4
	pkt[9] = 17             // UDP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)
	return pkt
}

func TestUnicastGameTrafficIsNotNoise(t *testing.T) {
	pkt := buildIPv4UDP([4]byte{10, 99, 0, 1}, [4]byte{10, 99, 0, 55}, 54321, 27015)
	info, ok := Parse(pkt)
	if !ok {
		t.Fatal("expected Parse to succeed")
	}
	if info.Noise {
		t.Errorf("expected unicast traffic to port 27015 to NOT be noise, got reason=%q", info.Reason)
	}
}

func TestMdnsIsNoise(t *testing.T) {
	pkt := buildIPv4UDP([4]byte{10, 99, 0, 1}, [4]byte{224, 0, 0, 251}, 5353, 5353)
	info, ok := Parse(pkt)
	if !ok {
		t.Fatal("expected Parse to succeed")
	}
	if !info.Noise {
		t.Error("expected mDNS traffic to be classified as noise")
	}
}

func TestNetbiosIsNoise(t *testing.T) {
	pkt := buildIPv4UDP([4]byte{10, 99, 0, 1}, [4]byte{10, 99, 0, 255}, 137, 137)
	info, ok := Parse(pkt)
	if !ok {
		t.Fatal("expected Parse to succeed")
	}
	if !info.Noise {
		t.Error("expected NetBIOS traffic to be classified as noise")
	}
	if info.Reason != "broadcast destination" && info.Reason != "NetBIOS Name Service" {
		t.Errorf("unexpected reason: %q", info.Reason)
	}
}

func TestSubnetBroadcastIsNoise(t *testing.T) {
	// broadcast address should be noise even on a normal port
	pkt := buildIPv4UDP([4]byte{10, 99, 0, 1}, [4]byte{10, 99, 0, 255}, 12345, 54321)
	info, ok := Parse(pkt)
	if !ok {
		t.Fatal("expected Parse to succeed")
	}
	if !info.Noise {
		t.Error("expected broadcast destination to be classified as noise regardless of port")
	}
}

func TestPublicAddressEndingIn255IsNotNoise(t *testing.T) {
	// public IP ending in .255 is not a broadcast
	pkt := buildIPv4UDP([4]byte{10, 66, 0, 2}, [4]byte{203, 0, 113, 255}, 54321, 27015)
	info, ok := Parse(pkt)
	if !ok {
		t.Fatal("expected Parse to succeed")
	}
	if info.Noise {
		t.Errorf("expected public unicast traffic ending in .255 to NOT be noise, got reason=%q", info.Reason)
	}
}

func TestShortPacketRejected(t *testing.T) {
	if _, ok := Parse([]byte{0x45, 0x00}); ok {
		t.Error("expected Parse to reject a too-short packet")
	}
}
