package main

import "testing"

// TestFlowIDCollision is the direct regression test for IDEAS.md's
// P0 #2: with the old info.SrcPort-only scheme, two flows sharing a
// source port but going to different destinations (routine for Steam
// Datagram Relay, which pings many relay POPs from one socket) got the
// same flow ID, and the server would silently write the second
// destination's traffic into the first destination's already-connected
// UDP socket. Keying by the full 4-tuple must give them distinct IDs.
func TestFlowIDCollision(t *testing.T) {
	ids := make(map[flowKey]uint16)
	var counter uint16

	sameSrcPort := uint16(54321)
	dstA := [4]byte{203, 0, 113, 10}
	dstB := [4]byte{203, 0, 113, 20}

	keyA := flowKey{srcPort: sameSrcPort, dst: dstA, dstPort: 27015}
	keyB := flowKey{srcPort: sameSrcPort, dst: dstB, dstPort: 27015}

	idA := allocFlowID(ids, &counter, keyA)
	idB := allocFlowID(ids, &counter, keyB)

	if idA == idB {
		t.Fatalf("two different destinations sharing a source port collided on flow ID %d — this is exactly the bug: traffic for one destination would be written to the other's socket", idA)
	}
}

// TestFlowIDStable checks the other half of correctness: repeated
// packets on the same flow (same 4-tuple) must keep resolving to the
// same ID, or replies would stop matching flows[flowID] on the client
// and get silently dropped.
func TestFlowIDStable(t *testing.T) {
	ids := make(map[flowKey]uint16)
	var counter uint16

	key := flowKey{srcPort: 40000, dst: [4]byte{1, 2, 3, 4}, dstPort: 443}

	first := allocFlowID(ids, &counter, key)
	second := allocFlowID(ids, &counter, key)
	third := allocFlowID(ids, &counter, key)

	if first != second || second != third {
		t.Fatalf("same flow key produced different IDs across calls: %d, %d, %d", first, second, third)
	}
}

// TestFlowIDThreeDistinctFlows rounds out the picture: a third,
// unrelated flow must get its own third ID, not collide with either of
// the first two.
func TestFlowIDThreeDistinctFlows(t *testing.T) {
	ids := make(map[flowKey]uint16)
	var counter uint16

	keyA := flowKey{srcPort: 1111, dst: [4]byte{10, 0, 0, 1}, dstPort: 80}
	keyB := flowKey{srcPort: 2222, dst: [4]byte{10, 0, 0, 2}, dstPort: 80}
	keyC := flowKey{srcPort: 1111, dst: [4]byte{10, 0, 0, 3}, dstPort: 27015}

	idA := allocFlowID(ids, &counter, keyA)
	idB := allocFlowID(ids, &counter, keyB)
	idC := allocFlowID(ids, &counter, keyC)

	if idA == idB || idB == idC || idA == idC {
		t.Fatalf("expected three distinct flow IDs, got %d, %d, %d", idA, idB, idC)
	}
}
