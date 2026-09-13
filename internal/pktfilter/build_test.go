package pktfilter

import (
	"bytes"
	"testing"
)

func TestBuildIPv4UDPRoundTripsThroughParse(t *testing.T) {
	src := [4]byte{10, 99, 0, 77}
	dst := [4]byte{10, 99, 0, 1}
	payload := []byte("response bytes")

	pkt := BuildIPv4UDP(src, dst, 27015, 54321, payload)

	info, ok := Parse(pkt)
	if !ok {
		t.Fatal("expected Parse to accept the built packet")
	}
	if !info.Src.Equal(net4(src)) {
		t.Errorf("src: got %v want %v", info.Src, net4(src))
	}
	if !info.Dst.Equal(net4(dst)) {
		t.Errorf("dst: got %v want %v", info.Dst, net4(dst))
	}
	if info.SrcPort != 27015 {
		t.Errorf("srcPort: got %d want 27015", info.SrcPort)
	}
	if info.DstPort != 54321 {
		t.Errorf("dstPort: got %d want 54321", info.DstPort)
	}
	if !bytes.Equal(info.Payload, payload) {
		t.Errorf("payload: got %q want %q", info.Payload, payload)
	}
}

func TestBuildIPv4UDPHeaderChecksumValid(t *testing.T) {
	pkt := BuildIPv4UDP([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1111, 2222, []byte("x"))

	// Recomputing the checksum over the header AS SENT (checksum field
	// included, not zeroed) must fold to exactly 0 for a valid checksum.
	var sum uint32
	header := pkt[0:20]
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if sum != 0xFFFF {
		t.Errorf("checksum invalid: folded sum = 0x%x, want 0xFFFF", sum)
	}
}

func net4(b [4]byte) []byte { return b[:] }
