package glue

import (
	"bytes"
	"net"
	"testing"
)

func TestOutboundRoundTrip(t *testing.T) {
	dst := net.IPv4(10, 99, 0, 77)
	payload := []byte("hello game server")

	wire, err := EncodeOutbound(4242, dst, 27015, payload)
	if err != nil {
		t.Fatal(err)
	}
	flowID, gotDst, dstPort, gotPayload, err := DecodeOutbound(wire)
	if err != nil {
		t.Fatalf("DecodeOutbound: %v", err)
	}
	if flowID != 4242 {
		t.Errorf("flowID: got %d want 4242", flowID)
	}
	if !gotDst.Equal(dst) {
		t.Errorf("dst: got %v want %v", gotDst, dst)
	}
	if dstPort != 27015 {
		t.Errorf("dstPort: got %d want 27015", dstPort)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload: got %q want %q", gotPayload, payload)
	}
}

func TestInboundRoundTrip(t *testing.T) {
	payload := []byte("response bytes")
	wire := EncodeInbound(9001, payload)

	flowID, gotPayload, err := DecodeInbound(wire)
	if err != nil {
		t.Fatalf("DecodeInbound: %v", err)
	}
	if flowID != 9001 {
		t.Errorf("flowID: got %d want 9001", flowID)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload: got %q want %q", gotPayload, payload)
	}
}

func TestDecodeRejectsWrongType(t *testing.T) {
	wire := EncodeInbound(1, []byte("x"))
	if _, _, _, _, err := DecodeOutbound(wire); err == nil {
		t.Error("expected DecodeOutbound to reject an inbound-tagged envelope")
	}
}

func TestDecodeRejectsShort(t *testing.T) {
	if _, _, _, _, err := DecodeOutbound([]byte{msgOutbound, 0, 1}); err == nil {
		t.Error("expected DecodeOutbound to reject a too-short envelope")
	}
}

func TestPathPingRoundTrip(t *testing.T) {
	wire := EncodePathPing(12345)
	if !IsPathPing(wire) || IsPing(wire) {
		t.Fatal("path ping must not be mistaken for a regular ping")
	}
	nonce, ok := DecodePathPing(wire)
	if !ok || nonce != 12345 {
		t.Fatalf("got nonce=%d ok=%v", nonce, ok)
	}
	if _, ok := DecodePathPing(EncodePing(1)); ok {
		t.Fatal("regular ping decoded as path ping")
	}
}

func TestEncodeOutboundRefusesIPv6(t *testing.T) {
	if _, err := EncodeOutbound(1, net.ParseIP("2001:db8::1"), 443, nil); err == nil {
		t.Fatal("IPv6 destination encoded (it would be sent to 0.0.0.0)")
	}
}
