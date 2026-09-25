package sched

import (
	"math"
	"time"
)

// Shaper paces a connection's writes to a fixed rate (a token bucket).
//
// The point is where the queue ends up, not the rate itself: if the
// tunnel pushes data faster than the slowest link on the way (the dorm
// uplink/downlink), the excess piles up in that link's router buffer,
// which this program can't see or reorder — and every game packet, even
// on a separate multipath connection, waits in it too. Pacing slightly
// below that link's real capacity moves the queue here instead, where
// the Scheduler decides what goes first. Same idea as CAKE/SQM's shaper
// on a home router.
//
// A nil *Shaper means unlimited. Not safe for concurrent use — one
// connection writer owns it.
type Shaper struct {
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
	sleep  func(time.Duration)
}

// NewShaper returns a Shaper for mbps megabits per second, or nil
// (unlimited) if mbps <= 0. The burst allowance is 5ms of data, but
// never less than two full packets, so pacing stays smooth without
// needing sub-millisecond sleeps.
func NewShaper(mbps float64) *Shaper {
	if mbps <= 0 {
		return nil
	}
	rate := mbps * 1e6 / 8
	burst := math.Max(rate*0.005, 2*maxPacket)
	return &Shaper{rate: rate, burst: burst, tokens: burst, now: time.Now, sleep: time.Sleep}
}

// Wait blocks until n more bytes may be written.
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
		// Go into debt and sleep it off; the next call's refill covers
		// the time slept.
		s.sleep(time.Duration(-s.tokens / s.rate * float64(time.Second)))
	}
}
