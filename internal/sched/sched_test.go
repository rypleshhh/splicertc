package sched

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// ipv4 builds a minimal IPv4 packet of total length size (>= 28) with
// the given protocol, addresses and ports, and optional flags/fragment
// offset word.
func ipv4(proto byte, src, dst [4]byte, sport, dport uint16, size int, fragWord uint16) []byte {
	if size < 28 {
		size = 28
	}
	p := make([]byte, size)
	p[0] = 0x45
	p[6], p[7] = byte(fragWord>>8), byte(fragWord)
	p[9] = proto
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	p[20], p[21] = byte(sport>>8), byte(sport)
	p[22], p[23] = byte(dport>>8), byte(dport)
	return p
}

var (
	ipA = [4]byte{10, 66, 0, 2}
	ipB = [4]byte{1, 2, 3, 4}
)

func TestFlowOf(t *testing.T) {
	tcp := FlowOf(ipv4(6, ipA, ipB, 5000, 443, 60, 0))
	if tcp.Proto != 6 || tcp.SrcPort != 5000 || tcp.DstPort != 443 || tcp.Src != ipA || tcp.Dst != ipB {
		t.Errorf("TCP key wrong: %+v", tcp)
	}
	udp := FlowOf(ipv4(17, ipA, ipB, 27015, 27016, 60, 0))
	if udp.SrcPort != 27015 || udp.DstPort != 27016 {
		t.Errorf("UDP ports wrong: %+v", udp)
	}
	// First fragment (MF set) and a later fragment must share one key.
	first := FlowOf(ipv4(17, ipA, ipB, 1111, 2222, 60, 0x2000))
	later := FlowOf(ipv4(17, ipA, ipB, 0x4142, 0x4344, 60, 0x0010))
	if first != later || first.SrcPort != 0 {
		t.Errorf("fragments should share a port-less key: first=%+v later=%+v", first, later)
	}
	if k := FlowOf([]byte{0x60, 0, 0}); k != (FlowKey{}) {
		t.Errorf("non-IPv4 should map to the zero key, got %+v", k)
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestSched(cfg Config) (*Scheduler, *fakeClock) {
	s := New(cfg)
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	s.now = c.now
	return s, c
}

func mustDequeue(t *testing.T, s *Scheduler) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.dequeueLocked()
	if !ok {
		t.Fatal("expected a packet, queue was empty")
	}
	return d
}

func pkt(tag byte, size int) []byte {
	b := make([]byte, size)
	b[0] = tag
	return b
}

// TestSparseFlowJumpsBacklog is the core property: once a bulk flow has
// been backlogged, a packet from a flow that just became active goes out
// next instead of waiting behind the whole backlog.
func TestSparseFlowJumpsBacklog(t *testing.T) {
	s, _ := newTestSched(Config{})
	bulk := FlowKey{Proto: 6, SrcPort: 1}
	game := FlowKey{Proto: 17, SrcPort: 2}

	for i := 0; i < 100; i++ {
		s.Enqueue(bulk, pkt('B', 1400))
	}
	for i := 0; i < 5; i++ {
		mustDequeue(t, s) // bulk is now an old, backlogged flow
	}
	s.Enqueue(game, pkt('G', 120))

	if got := mustDequeue(t, s); got[0] != 'G' {
		t.Fatalf("expected the game packet next, got a %q packet — sparse flow waited behind the backlog", got[0])
	}
}

func TestPerFlowOrderPreserved(t *testing.T) {
	s, _ := newTestSched(Config{})
	a := FlowKey{Proto: 6, SrcPort: 1}
	b := FlowKey{Proto: 6, SrcPort: 2}
	for i := 0; i < 20; i++ {
		s.Enqueue(a, []byte{'a', byte(i)})
		s.Enqueue(b, []byte{'b', byte(i)})
	}
	next := map[byte]byte{}
	for i := 0; i < 40; i++ {
		d := mustDequeue(t, s)
		if d[1] != next[d[0]] {
			t.Fatalf("flow %q reordered: got seq %d, want %d", d[0], d[1], next[d[0]])
		}
		next[d[0]]++
	}
}

// TestBulkFlowsShareFairly: two continuously backlogged flows get
// roughly equal bytes, whatever their packet sizes.
func TestBulkFlowsShareFairly(t *testing.T) {
	s, _ := newTestSched(Config{})
	big := FlowKey{Proto: 6, SrcPort: 1}
	small := FlowKey{Proto: 6, SrcPort: 2}
	for i := 0; i < 400; i++ {
		s.Enqueue(big, pkt('B', 1400))
		s.Enqueue(small, pkt('S', 200))
	}
	got := map[byte]int{}
	for i := 0; i < 300; i++ {
		d := mustDequeue(t, s)
		got[d[0]] += len(d)
	}
	ratio := float64(got['B']) / float64(got['S'])
	if ratio < 0.7 || ratio > 1.4 {
		t.Errorf("unfair byte split: big=%d small=%d (ratio %.2f)", got['B'], got['S'], ratio)
	}
}

func TestOverflowDropsFromFattestFlow(t *testing.T) {
	s, _ := newTestSched(Config{LimitBytes: 10_000})
	hog := FlowKey{Proto: 6, SrcPort: 1}
	quiet := FlowKey{Proto: 17, SrcPort: 2}
	s.Enqueue(quiet, pkt('Q', 100))
	for i := 0; i < 50; i++ {
		s.Enqueue(hog, pkt('H', 1400))
	}
	st := s.Stats()
	if st.QueuedBytes > 10_000 {
		t.Fatalf("queue over limit: %d bytes", st.QueuedBytes)
	}
	if st.OverflowDrops == 0 {
		t.Fatal("expected overflow drops")
	}
	if got := mustDequeue(t, s); got[0] != 'Q' {
		t.Fatalf("the quiet flow's packet should have survived the overflow, got %q", got[0])
	}
}

// TestCodelDropsStandingQueue: a queue that stays well above target for
// longer than an interval gets packets dropped; one that drains quickly
// doesn't.
func TestCodelDropsStandingQueue(t *testing.T) {
	s, clk := newTestSched(Config{})
	bulk := FlowKey{Proto: 6, SrcPort: 1}
	for i := 0; i < 300; i++ {
		s.Enqueue(bulk, pkt('B', 1400))
	}
	// Drain slowly: 2ms per packet, so every packet waits far longer
	// than the 5ms target, for much longer than the 100ms interval.
	for i := 0; i < 200; i++ {
		clk.advance(2 * time.Millisecond)
		s.mu.Lock()
		_, ok := s.dequeueLocked()
		s.mu.Unlock()
		if !ok {
			break
		}
	}
	if s.Stats().CodelDrops == 0 {
		t.Fatal("expected CoDel to drop from a persistently standing queue")
	}

	s2, clk2 := newTestSched(Config{})
	for i := 0; i < 50; i++ {
		s2.Enqueue(bulk, pkt('B', 1400))
		clk2.advance(time.Millisecond)
		mustDequeue(t, s2) // drained as fast as it fills
	}
	if d := s2.Stats().CodelDrops; d != 0 {
		t.Fatalf("expected no drops on a queue that never stands, got %d", d)
	}
}

func TestIdleFlowsAreForgotten(t *testing.T) {
	s, _ := newTestSched(Config{})
	for i := 0; i < 10; i++ {
		s.Enqueue(FlowKey{Proto: 17, SrcPort: uint16(i)}, pkt('x', 100))
	}
	for i := 0; i < 10; i++ {
		mustDequeue(t, s)
	}
	s.mu.Lock()
	_, ok := s.dequeueLocked()
	s.mu.Unlock()
	if ok {
		t.Fatal("queue should be empty")
	}
	if n := s.Stats().ActiveFlows; n != 0 {
		t.Fatalf("expected idle flows to be dropped from the map, %d remain", n)
	}
}

func TestCloseUnblocksDequeue(t *testing.T) {
	s := New(Config{})
	done := make(chan bool)
	go func() {
		_, ok := s.Dequeue()
		done <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	s.Close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Dequeue on a closed scheduler should report ok=false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close didn't unblock Dequeue")
	}
}

func TestDequeueWakesOnEnqueue(t *testing.T) {
	s := New(Config{})
	got := make(chan []byte)
	go func() {
		d, _ := s.Dequeue()
		got <- d
	}()
	time.Sleep(20 * time.Millisecond)
	s.Enqueue(FlowKey{}, []byte("hi"))
	select {
	case d := <-got:
		if !bytes.Equal(d, []byte("hi")) {
			t.Fatalf("got %q", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dequeue didn't wake up on Enqueue")
	}
}

func TestShaperPacesToRate(t *testing.T) {
	sh := NewShaper(8) // 8 Mbit/s = 1,000,000 bytes/s
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	sh.now = clk.now
	sh.sleep = clk.advance

	start := clk.t
	const total = 1_000_000
	for sent := 0; sent < total; sent += 1000 {
		sh.Wait(1000)
	}
	elapsed := clk.t.Sub(start)
	// One second of data, minus the initial burst allowance.
	if elapsed < 950*time.Millisecond || elapsed > 1050*time.Millisecond {
		t.Fatalf("1 MB at 1 MB/s took %v, want ~1s", elapsed)
	}
}

func TestNilShaperIsUnlimited(t *testing.T) {
	var sh *Shaper
	sh.Wait(1 << 30) // must not panic or block
	if NewShaper(0) != nil {
		t.Fatal("NewShaper(0) should be nil (unlimited)")
	}
}

// TestPathWriterStalledPathNeverBlocks: a path whose peer never reads
// must not make Send block — that's the whole point of it.
func TestPathWriterStalledPathNeverBlocks(t *testing.T) {
	stalled, other := net.Pipe() // nobody reads `other`: every Write blocks
	defer other.Close()
	pw := NewPathWriter(stalled, 4, 0)
	defer pw.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			pw.Send([]byte("frame"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Send blocked on a stalled path")
	}
	if pw.Drops() == 0 {
		t.Fatal("expected drops on a stalled path")
	}
}

func TestPathWriterDeliversInOrder(t *testing.T) {
	a, b := net.Pipe()
	pw := NewPathWriter(a, 64, 0)
	defer pw.Close()

	var mu sync.Mutex
	var got []byte
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		for len(got) < 10 {
			if _, err := b.Read(buf); err != nil {
				break
			}
			mu.Lock()
			got = append(got, buf[0])
			mu.Unlock()
		}
		close(readDone)
	}()
	for i := byte(0); i < 10; i++ {
		pw.Send([]byte{i})
	}
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("frames not delivered")
	}
	for i, v := range got {
		if v != byte(i) {
			t.Fatalf("out of order: %v", got)
		}
	}
}

func TestPathWriterSkipsStaleFrames(t *testing.T) {
	a, b := net.Pipe()
	pw := NewPathWriter(a, 8, 10*time.Millisecond)
	defer pw.Close()

	// Block the writer on a first frame nobody reads yet, queue more
	// behind it, let them go stale, then start reading.
	pw.Send([]byte{1})
	time.Sleep(5 * time.Millisecond)
	pw.Send([]byte{2})
	pw.Send([]byte{3})
	time.Sleep(50 * time.Millisecond)

	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != nil || buf[0] != 1 {
		t.Fatalf("expected the in-flight frame first, got %v (%v)", buf[0], err)
	}
	pw.Send([]byte{4})
	if _, err := b.Read(buf); err != nil || buf[0] != 4 {
		t.Fatalf("expected stale frames 2,3 to be skipped and 4 delivered, got %v", buf[0])
	}
}
