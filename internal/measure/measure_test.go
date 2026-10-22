package measure

import (
	"testing"
	"time"
)

func TestBasicRoundTrip(t *testing.T) {
	s := New()
	s.OnSend(1)
	time.Sleep(5 * time.Millisecond)
	s.OnRecv(1)

	sum := s.Snapshot(time.Second)
	if sum.Sent != 1 || sum.Received != 1 {
		t.Fatalf("sent/recv: got %d/%d want 1/1", sum.Sent, sum.Received)
	}
	if sum.LossPct != 0 {
		t.Errorf("loss: got %.1f want 0", sum.LossPct)
	}
	if sum.MeanRTT < 4*time.Millisecond {
		t.Errorf("mean RTT implausibly low: %v", sum.MeanRTT)
	}
}

func TestLossCounted(t *testing.T) {
	s := New()
	s.OnSend(1)
	s.OnSend(2) // never answered
	s.OnRecv(1)

	// nonce 2 had no reply, should count as lost
	time.Sleep(10 * time.Millisecond)
	sum := s.Snapshot(5 * time.Millisecond)
	if sum.Sent != 2 || sum.Received != 1 {
		t.Fatalf("got sent=%d recv=%d", sum.Sent, sum.Received)
	}
	if sum.LossPct != 50 {
		t.Errorf("loss: got %.1f want 50", sum.LossPct)
	}
}

func TestDuplicateEchoIgnored(t *testing.T) {
	s := New()
	s.OnSend(7)
	s.OnRecv(7)
	s.OnRecv(7) // duplicate

	sum := s.Snapshot(time.Second)
	if sum.Received != 1 {
		t.Errorf("duplicate echo should not double-count: received=%d", sum.Received)
	}
}

// A long run must not keep every sample.
func TestSamplesAreBounded(t *testing.T) {
	s := New()
	for i := uint64(0); i < maxSamples+500; i++ {
		s.OnSend(i)
		s.OnRecv(i)
	}
	if len(s.rtts) != maxSamples {
		t.Fatalf("kept %d samples, want %d", len(s.rtts), maxSamples)
	}
	if sum := s.Snapshot(time.Second); sum.Received != maxSamples+500 {
		t.Fatalf("received counter = %d", sum.Received)
	}
}

// A ping sent just now is neither sent nor lost yet.
func TestInFlightNotCountedAsLoss(t *testing.T) {
	s := New()
	s.OnSend(1)
	s.OnRecv(1)
	s.OnSend(2) // in flight

	sum := s.Snapshot(time.Hour)
	if sum.Sent != 1 || sum.Received != 1 || sum.LossPct != 0 {
		t.Fatalf("got sent=%d recv=%d loss=%.1f, want 1/1/0", sum.Sent, sum.Received, sum.LossPct)
	}

	// once it's older than the timeout it is lost
	time.Sleep(10 * time.Millisecond)
	sum = s.Snapshot(5 * time.Millisecond)
	if sum.Sent != 2 || sum.LossPct != 50 {
		t.Fatalf("got sent=%d loss=%.1f, want 2/50", sum.Sent, sum.LossPct)
	}
}

// Unanswered pings must not pile up when Snapshot is never called.
func TestPendingBoundedWithoutSnapshot(t *testing.T) {
	s := New()
	for i := uint64(0); i < 10*minScanAt; i++ {
		s.OnSend(i)
		s.sentAt[i] = time.Now().Add(-2 * maxPendingAge) // never answered
	}
	if n := len(s.sentAt); n > minScanAt {
		t.Fatalf("%d pings pending, want at most %d", n, minScanAt)
	}
	sum := s.Snapshot(time.Second)
	if sum.Sent != 10*minScanAt || sum.LossPct != 100 {
		t.Fatalf("got sent=%d loss=%.1f", sum.Sent, sum.LossPct)
	}
}

// Recent pending pings are kept, the scan just gets rarer.
func TestPendingRecentKept(t *testing.T) {
	s := New()
	for i := uint64(0); i < 3*minScanAt; i++ {
		s.OnSend(i)
	}
	if n := len(s.sentAt); n != 3*minScanAt {
		t.Fatalf("recent pings were dropped: %d pending", n)
	}
}
