package sched

import (
	"math"
	"time"
)

// Shaper limits write speed with a token bucket. If we send a bit slower
// than the real link, the queue builds up in our Scheduler instead of
// the router, where we can't reorder it.
//
// nil Shaper means no limit. Not safe for concurrent use.
type Shaper struct {
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
	sleep  func(time.Duration)
}

// NewShaper returns nil if mbps <= 0. Burst is 5ms of data but at least
// two full packets.
func NewShaper(mbps float64) *Shaper {
	if mbps <= 0 {
		return nil
	}
	rate := mbps * 1e6 / 8
	burst := math.Max(rate*0.005, 2*maxPacket)
	return &Shaper{rate: rate, burst: burst, tokens: burst, now: time.Now, sleep: time.Sleep}
}

// Wait blocks until n more bytes can be sent.
func (s *Shaper) Wait(n int) {
	if s == nil {
		return
	}
	now := s.now()
	if !s.last.IsZero() {
		s.tokens = math.Min(s.burst, s.tokens+now.Sub(s.last).Seconds()*s.rate)
	}
	s.last = now
	s.tokens -= float64(n)
	if s.tokens < 0 {
		s.sleep(time.Duration(-s.tokens / s.rate * float64(time.Second)))
	}
}
