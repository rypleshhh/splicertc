// Package measure collects ping RTTs between client and server and
// calculates latency, jitter and loss.
package measure

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Only the last maxSamples RTTs are kept for min/mean/p95/max. With a
// ping every 33ms that's the last ~5 minutes; keeping all of them would
// grow forever and make every Snapshot slower.
const maxSamples = 10000

// Pings without a reply for this long are forgotten (counted as lost)
// even if Snapshot is never called, so sentAt can't grow forever.
// OnSend checks only when sentAt has grown to scanAt entries, so the
// check costs nothing per ping on average.
const (
	maxPendingAge = 30 * time.Second
	minScanAt     = 1024
)

// Stats tracks outstanding pings and completed round trips.
type Stats struct {
	mu        sync.Mutex
	sentAt    map[uint64]time.Time
	scanAt    int             // len(sentAt) at which OnSend expires old pings
	rtts      []time.Duration // ring buffer, next points to the oldest
	next      int
	sent      int
	received  int
	lastRTT   time.Duration
	jitterAcc float64 // ms, like RTP (RFC 3550)
	haveLast  bool
}

func New() *Stats {
	return &Stats{sentAt: make(map[uint64]time.Time), scanAt: minScanAt}
}

func (s *Stats) OnSend(nonce uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sentAt[nonce] = time.Now()
	s.sent++
	if len(s.sentAt) >= s.scanAt {
		s.expireOlderThan(maxPendingAge)
		s.scanAt = max(2*len(s.sentAt), minScanAt)
	}
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
	if len(s.rtts) < maxSamples {
		s.rtts = append(s.rtts, rtt)
	} else {
		s.rtts[s.next] = rtt
		s.next = (s.next + 1) % maxSamples
	}
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
	// Sent doesn't include pings still waiting for a reply
	Sent, Received  int
	LossPct         float64
	MinRTT, MaxRTT  time.Duration
	MeanRTT, P95RTT time.Duration
	JitterMS        float64
}

// Snapshot returns the current stats. Pings without a reply after
// lossTimeout count as lost; younger ones are still in flight and not
// counted at all. Sent/received/loss are for the whole run, the RTT
// numbers for the last maxSamples replies.
func (s *Stats) Snapshot(lossTimeout time.Duration) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireOlderThan(lossTimeout)

	// what's left in sentAt was sent less than lossTimeout ago
	sent := s.sent - len(s.sentAt)
	sum := Summary{Sent: sent, Received: s.received, JitterMS: s.jitterAcc}
	if sent > 0 {
		sum.LossPct = 100 * float64(sent-s.received) / float64(sent)
	}
	if len(s.rtts) == 0 {
		return sum
	}

	sorted := make([]time.Duration, len(s.rtts))
	copy(sorted, s.rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

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
