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

	// nonce 2 is still outstanding; with a tiny timeout it should count
	// as lost.
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
	s.OnRecv(7) // duplicate copy arriving via a second path

	sum := s.Snapshot(time.Second)
	if sum.Received != 1 {
		t.Errorf("duplicate echo should not double-count: received=%d", sum.Received)
	}
}
