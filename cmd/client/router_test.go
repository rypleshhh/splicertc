package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"tcp-dormtun/internal/pktfilter"
)

// fakePorts stands in for procmap. refresh does synchronously what the
// background refresher does, so the next classify sees the new table.
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

// A new game socket that isn't in the cached table yet: the first packet
// is dropped and a refresh requested (the read loop must not wait for
// the Windows API), the next one goes over glue.
func TestRouterRefreshesOnMiss(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: "game.exe"}}
	r := testRouter(f)
	now := time.Now()
	if _, send := r.classify(gameKey, now); send {
		t.Fatal("unknown owner should drop the packet")
	}
	if f.refreshes != 1 {
		t.Fatalf("expected one refresh request on miss, got %d", f.refreshes)
	}
	if glue, send := r.classify(gameKey, now.Add(time.Millisecond)); !send || !glue {
		t.Fatalf("expected glue after the refresh, got glue=%v send=%v", glue, send)
	}
	r.classify(gameKey, now.Add(2*time.Millisecond))
	if f.refreshes != 1 {
		t.Fatalf("decided flow requested a refresh, %d requests", f.refreshes)
	}
}

// A port already in the table is decided without a refresh.
func TestRouterKnownPortNoRefresh(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: "game.exe"}}
	f.refresh()
	f.refreshes = 0
	r := testRouter(f)
	if glue, send := r.classify(gameKey, time.Now()); !glue || !send {
		t.Fatalf("expected glue, got glue=%v send=%v", glue, send)
	}
	if f.refreshes != 0 {
		t.Fatalf("known port requested %d refreshes", f.refreshes)
	}
}

// Once decided, a flow never switches channel, even if the table changes.
func TestRouterDecisionIsSticky(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: "game.exe"}}
	f.refresh()
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
	// this packet asks for a refresh that finds the port
	r.classify(gameKey, now.Add(200*time.Millisecond))
	if glue, send := r.classify(gameKey, now.Add(300*time.Millisecond)); !glue || !send {
		t.Fatalf("expected glue once the port is known, got glue=%v send=%v", glue, send)
	}
}

// System services have a port but no name: vpn, decided right away.
func TestRouterNamelessOwnerGoesVPN(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: ""}}
	f.refresh()
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

// kick never blocks, and kicks during a run are merged into one more run.
func TestRefresherMergesKicks(t *testing.T) {
	var runs atomic.Int32
	started := make(chan struct{}, 10)
	release := make(chan struct{})
	r := startRefresher(func() {
		runs.Add(1)
		started <- struct{}{}
		<-release
	}, time.Millisecond)

	r.kick()
	<-started
	for i := 0; i < 100; i++ {
		r.kick() // fn is blocked, must not block here
	}
	release <- struct{}{}
	<-started
	release <- struct{}{}

	time.Sleep(50 * time.Millisecond)
	if n := runs.Load(); n != 2 {
		t.Fatalf("got %d runs, want 2", n)
	}
}

// udpPacket builds a parsed UDP packet from 10.66.0.2.
func udpPacket(t *testing.T, srcPort uint16, dst [4]byte, dstPort uint16) pktfilter.Info {
	t.Helper()
	pkt := pktfilter.BuildIPv4UDP([4]byte{10, 66, 0, 2}, dst, srcPort, dstPort, []byte("x"))
	info, ok := pktfilter.Parse(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	return info
}

// A UDP fragment to a game server must not go over vpn while the rest of
// the flow goes over glue: the server would see two source addresses.
func TestGameSplitFragments(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{5000: "game.exe", 6000: "browser.exe"}}
	f.refresh()
	s := &gameSplit{router: testRouter(f), flows: newFlowTable()}
	now := time.Now()
	game := [4]byte{1, 2, 3, 4}
	other := [4]byte{5, 6, 7, 8}

	fragment := func(dst [4]byte) pktfilter.Info {
		return pktfilter.Info{Version: 4, Proto: 17, Src: net.IPv4(10, 66, 0, 2).To4(), Dst: net.IP(dst[:]), Fragment: true}
	}

	// before any glue flow fragments go over vpn
	if a, _ := s.decide(fragment(game), now); a != toVPN {
		t.Fatalf("fragment with no glue flow: got %v, want toVPN", a)
	}

	if a, _ := s.decide(udpPacket(t, 5000, game, 27015), now); a != toGlue {
		t.Fatalf("game packet: got %v, want toGlue", a)
	}
	if a, _ := s.decide(udpPacket(t, 6000, other, 443), now); a != toVPN {
		t.Fatalf("browser packet: got %v, want toVPN", a)
	}

	cases := []struct {
		name string
		dst  [4]byte
		want packetAction
	}{
		{"to game server", game, dropFragment},
		{"to other server", other, toVPN},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if a, _ := s.decide(fragment(c.dst), now); a != c.want {
				t.Fatalf("got %v, want %v", a, c.want)
			}
		})
	}

	// after the glue flow expired fragments go over vpn again
	s.flows.sweep(now.Add(2*time.Minute), time.Minute)
	if a, _ := s.decide(fragment(game), now.Add(2*time.Minute)); a != toVPN {
		t.Fatalf("fragment after the flow expired: got %v, want toVPN", a)
	}
}

// Non-UDP and unknown-owner packets.
func TestGameSplitOther(t *testing.T) {
	f := &fakePorts{table: map[uint16]string{}}
	s := &gameSplit{router: testRouter(f), flows: newFlowTable()}
	now := time.Now()
	tcp := pktfilter.Info{Version: 4, Proto: 6, Src: net.IPv4(10, 66, 0, 2).To4(), Dst: net.IPv4(1, 2, 3, 4).To4()}
	if a, _ := s.decide(tcp, now); a != toVPN {
		t.Fatalf("tcp: got %v, want toVPN", a)
	}
	if a, _ := s.decide(udpPacket(t, 5000, [4]byte{1, 2, 3, 4}, 27015), now); a != dropUnknown {
		t.Fatalf("unknown owner: got %v, want dropUnknown", a)
	}
}
