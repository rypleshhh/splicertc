// Package measure collects ping RTTs between client and server and
// calculates latency, jitter and loss.
package measure

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// Stats tracks outstanding pings and completed round trips.
type Stats struct {
	mu        sync.Mutex
	sentAt    map[uint64]time.Time
	rtts      []time.Duration
	sent      int
	received  int
	lastRTT   time.Duration
	jitterAcc float64 // ms, like RTP (RFC 3550)
	haveLast  bool
}

func New() *Stats {
	return &Stats{sentAt: make(map[uint64]time.Time)}
}

func (s *Stats) OnSend(nonce uint64) {
	s.mu.Lock()
	s.sentAt[nonce] = time.Now()
	s.sent++
	s.mu.Unlock()
}

// OnRecv records a ping reply. Duplicates from other paths are ignored.
func (s *Stats) OnRecv(nonce uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sentAt, ok := s.sentAt[nonce]
	if !ok {
		return
	}
	delete(s.sentAt, nonce)

	rtt := time.Since(sentAt)
	s.rtts = append(s.rtts, rtt)
	s.received++

	// smoothed difference between consecutive RTTs
	if s.haveLast {
		d := math.Abs(float64(rtt-s.lastRTT) / float64(time.Millisecond))
		s.jitterAcc += (d - s.jitterAcc) / 16
	}
	s.lastRTT = rtt
	s.haveLast = true
}

// expireOlderThan forgets pings older than d (they count as lost).
func (s *Stats) expireOlderThan(d time.Duration) {
	cutoff := time.Now().Add(-d)
	for nonce, t := range s.sentAt {
		if t.Before(cutoff) {
			delete(s.sentAt, nonce)
		}
	}
}

type Summary struct {
	Sent, Received  int
	LossPct         float64
	MinRTT, MaxRTT  time.Duration
	MeanRTT, P95RTT time.Duration
	JitterMS        float64
}

// Snapshot returns the current stats. Pings without a reply after
// lossTimeout count as lost.
func (s *Stats) Snapshot(lossTimeout time.Duration) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireOlderThan(lossTimeout)

	sum := Summary{Sent: s.sent, Received: s.received, JitterMS: s.jitterAcc}
	if s.sent > 0 {
		sum.LossPct = 100 * float64(s.sent-s.received) / float64(s.sent)
	}
	if len(s.rtts) == 0 {
		return sum
	}

	sorted := make([]time.Duration, len(s.rtts))
	copy(sorted, s.rtts)
	// insertion sort, not many samples
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	sum.MinRTT = sorted[0]
	sum.MaxRTT = sorted[len(sorted)-1]
	var total time.Duration
	for _, r := range sorted {
		total += r
	}
	sum.MeanRTT = total / time.Duration(len(sorted))
	sum.P95RTT = sorted[int(math.Ceil(0.95*float64(len(sorted))))-1]
	return sum
}

func (s Summary) String() string {
	return fmt.Sprintf(
		"sent=%d recv=%d loss=%.1f%% | rtt min/mean/p95/max = %v/%v/%v/%v | jitter=%.1fms",
		s.Sent, s.Received, s.LossPct,
		s.MinRTT.Round(time.Microsecond*100),
		s.MeanRTT.Round(time.Microsecond*100),
		s.P95RTT.Round(time.Microsecond*100),
		s.MaxRTT.Round(time.Microsecond*100),
		s.JitterMS,
	)
}
