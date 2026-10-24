package main

import (
	"testing"
	"time"
)

func fi(srcPort uint16, dst [4]byte, dstPort uint16) flowInfo {
	return flowInfo{origSrc: [4]byte{10, 66, 0, 2}, origDst: dst, origSrcPort: srcPort, origDstPort: dstPort}
}

// Same source port, different destinations -> different IDs.
func TestFlowIDCollision(t *testing.T) {
	tab := newFlowTable()
	now := time.Now()
	idA, _ := tab.id(fi(54321, [4]byte{203, 0, 113, 10}, 27015), now)
	idB, _ := tab.id(fi(54321, [4]byte{203, 0, 113, 20}, 27015), now)
	if idA == idB {
		t.Fatalf("two different destinations sharing a source port got the same flow ID %d", idA)
	}
}

// Same flow should always get the same ID.
func TestFlowIDStable(t *testing.T) {
	tab := newFlowTable()
	now := time.Now()
	f := fi(40000, [4]byte{1, 2, 3, 4}, 443)
	first, _ := tab.id(f, now)
	second, _ := tab.id(f, now)
	third, _ := tab.id(f, now)
	if first != second || second != third {
		t.Fatalf("same flow produced different IDs across calls: %d, %d, %d", first, second, third)
	}
}

func TestFlowIDThreeDistinctFlows(t *testing.T) {
	tab := newFlowTable()
	now := time.Now()
	idA, _ := tab.id(fi(1111, [4]byte{10, 0, 0, 1}, 80), now)
	idB, _ := tab.id(fi(2222, [4]byte{10, 0, 0, 2}, 80), now)
	idC, _ := tab.id(fi(1111, [4]byte{10, 0, 0, 3}, 27015), now)
	if idA == idB || idB == idC || idA == idC {
		t.Fatalf("expected three distinct flow IDs, got %d, %d, %d", idA, idB, idC)
	}
}

// After 65536 flows the counter wraps; a long-lived flow must keep its
// ID and no new flow may get it.
func TestFlowIDWrapSkipsUsedIDs(t *testing.T) {
	tab := newFlowTable()
	start := time.Now()
	game := fi(5000, [4]byte{9, 9, 9, 9}, 27015)
	gameID, _ := tab.id(game, start)

	for i := 0; i < 200000; i++ {
		now := start.Add(time.Duration(i) * time.Millisecond)
		tab.id(game, now) // the game flow stays active
		dst := [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}
		id, ok := tab.id(fi(6000, dst, 53), now)
		if !ok {
			t.Fatalf("flow %d: no free ID", i)
		}
		if id == gameID {
			t.Fatalf("flow %d got the ID of the active game flow", i)
		}
		if i%1000 == 0 {
			tab.sweep(now, 500*time.Millisecond)
		}
	}
	if got, _ := tab.id(game, start); got != gameID {
		t.Fatalf("game flow ID changed from %d to %d", gameID, got)
	}
}

func TestFlowTableFull(t *testing.T) {
	tab := newFlowTable()
	now := time.Now()
	for i := 0; i < 1<<16; i++ {
		if _, ok := tab.id(fi(uint16(i), [4]byte{1, 1, 1, 1}, 1), now); !ok {
			t.Fatalf("flow %d: table full too early", i)
		}
	}
	if _, ok := tab.id(fi(1, [4]byte{2, 2, 2, 2}, 1), now); ok {
		t.Fatal("expected no free ID with 65536 active flows")
	}
}

func TestFlowSweepAndReplyActivity(t *testing.T) {
	tab := newFlowTable()
	start := time.Now()
	idA, _ := tab.id(fi(1, [4]byte{1, 1, 1, 1}, 1), start)
	idB, _ := tab.id(fi(2, [4]byte{1, 1, 1, 1}, 1), start)

	// only replies on A, they count as activity
	tab.lookup(idA, start.Add(50*time.Second))
	if n := tab.sweep(start.Add(70*time.Second), time.Minute); n != 1 {
		t.Fatalf("expected 1 flow removed, got %d", n)
	}
	if _, ok := tab.lookup(idA, start.Add(70*time.Second)); !ok {
		t.Fatal("flow with recent replies was removed")
	}
	if _, ok := tab.lookup(idB, start.Add(70*time.Second)); ok {
		t.Fatal("idle flow was not removed")
	}
}

// hasDst follows the flows to a destination until the last one expires.
func TestFlowTableHasDst(t *testing.T) {
	tab := newFlowTable()
	start := time.Now()
	dst := [4]byte{1, 2, 3, 4}
	tab.id(fi(1, dst, 27015), start)
	tab.id(fi(2, dst, 27015), start.Add(30*time.Second))
	if !tab.hasDst(dst) || tab.hasDst([4]byte{5, 6, 7, 8}) {
		t.Fatal("hasDst wrong after adding flows")
	}
	tab.sweep(start.Add(70*time.Second), time.Minute)
	if !tab.hasDst(dst) {
		t.Fatal("destination forgotten while a flow to it is active")
	}
	tab.sweep(start.Add(2*time.Minute), time.Minute)
	if tab.hasDst(dst) {
		t.Fatal("destination kept after all its flows expired")
	}
}
