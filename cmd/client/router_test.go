package main

import (
	"testing"
	"time"
)

type fakePorts struct {
	table     map[uint16]string // what refresh would load
	loaded    map[uint16]string
	refreshes int
}

func (f *fakePorts) owner(p uint16) (string, bool) {
	n, ok := f.loaded[p]
	return n, ok
}

func (f *fakePorts) refresh() {
	f.refreshes++
	f.loaded = make(map[uint16]string)
	for k, v := range f.table {
		f.loaded[k] = v
	}
}

func testRouter(f *fakePorts) *udpRouter {
	return newUDPRouter(f.owner, f.refresh, func(n string) bool { return n == "game.exe" })
}

var gameKey = flowKey{srcPort: 5000, dst: [4]byte{1, 2, 3, 4}, dstPort: 27015}

// A new game socket that isn't in the cached table yet: refresh right
// away and send it over glue from the first packet.
func TestRouterRefreshesOnMiss(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: "game.exe"}}
	r := testRouter(f)
	glue, send := r.classify(gameKey, time.Now())
	if !send || !glue {
		t.Fatalf("expected glue on the first packet, got glue=%v send=%v", glue, send)
	}
	if f.refreshes != 1 {
		t.Fatalf("expected one refresh on miss, got %d", f.refreshes)
	}
}

// Once decided, a flow never switches channel, even if the table changes.
func TestRouterDecisionIsSticky(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: "game.exe"}}
	r := testRouter(f)
	now := time.Now()
	r.classify(gameKey, now)

	f.table = map[uint16]string{5000: "other.exe"}
	f.refresh()
	if glue, send := r.classify(gameKey, now.Add(time.Second)); !glue || !send {
		t.Fatal("flow switched channel after the port table changed")
	}
}

// Unknown owner: drop packets for a while (don't start the flow on vpn
// and move it later), then give up and use vpn.
func TestRouterUnknownPortWaitsThenVPN(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{}}
	r := testRouter(f)
	now := time.Now()
	if _, send := r.classify(gameKey, now); send {
		t.Fatal("unknown owner should drop the packet at first")
	}
	if _, send := r.classify(gameKey, now.Add(500*time.Millisecond)); send {
		t.Fatal("still within the wait time, should drop")
	}
	glue, send := r.classify(gameKey, now.Add(1100*time.Millisecond))
	if !send || glue {
		t.Fatalf("after the wait the flow should go over vpn, got glue=%v send=%v", glue, send)
	}
}

// A port that shows up late (socket opened right before sending) is
// still classified correctly.
func TestRouterPortAppearsLater(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{}}
	r := testRouter(f)
	now := time.Now()
	r.classify(gameKey, now)
	f.table[5000] = "game.exe"
	if glue, send := r.classify(gameKey, now.Add(200*time.Millisecond)); !glue || !send {
		t.Fatalf("expected glue once the port is known, got glue=%v send=%v", glue, send)
	}
}

// System services have a port but no name: vpn, decided right away.
func TestRouterNamelessOwnerGoesVPN(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: ""}}
	r := testRouter(f)
	if glue, send := r.classify(gameKey, time.Now()); glue || !send {
		t.Fatalf("expected vpn, got glue=%v send=%v", glue, send)
	}
}

func TestRouterSweep(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: "game.exe"}}
	r := testRouter(f)
	now := time.Now()
	r.classify(gameKey, now)
	r.sweep(now.Add(2*time.Minute), time.Minute)
	if len(r.routes) != 0 {
		t.Fatal("idle route was not removed")
	}
}
