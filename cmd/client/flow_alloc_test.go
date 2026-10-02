package main

import "testing"

// Same source port, different destinations -> different IDs.
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
		t.Fatalf("two different destinations sharing a source port got the same flow ID %d", idA)
	}
}

// Same flow should always get the same ID.
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
