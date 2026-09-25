package sched

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// Config tunes a Scheduler. Zero values take the defaults below, which
// are the Linux fq_codel defaults except for LimitBytes (Linux's 32 MB
// memory cap is sized for a router's whole interface; this queue sits in
// front of one tunnel connection).
type Config struct {
	Quantum    int           // bytes a flow may send per round-robin turn
	LimitBytes int           // hard cap on total queued bytes (safety net; CoDel does the real work)
	Target     time.Duration // CoDel: acceptable standing queue delay
	Interval   time.Duration // CoDel: how long delay must stay above Target before dropping
}

const (
	defaultQuantum    = 1514
	defaultLimitBytes = 2 << 20
	defaultTarget     = 5 * time.Millisecond
	defaultInterval   = 100 * time.Millisecond

	// maxPacket mirrors CoDel's MAXPACKET: a queue holding no more than
	// about one full packet is never considered "standing", however long
	// that one packet waited.
	maxPacket = 1514
)

// Stats is a snapshot of a Scheduler's counters.
type Stats struct {
	Enqueued, Dequeued        uint64
	CodelDrops, OverflowDrops uint64
	QueuedBytes, ActiveFlows  int
}

// Scheduler is an FQ-CoDel queue (RFC 8290): packets are sorted into
// per-flow queues served by deficit round robin, flows that have just
// become active ("sparse" flows — a game tick, a voice frame, a DNS
// query, a TCP ACK) are served ahead of flows that have been backlogged
// for a while, and each flow queue runs CoDel (RFC 8289), which drops
// from a flow whose queue has stayed above a few milliseconds of delay
// for a whole interval — the signal that makes the TCP connections
// inside the tunnel slow down instead of parking megabytes here.
//
// Net effect: a download shares bandwidth fairly with everything else
// but can no longer make a game or voice packet wait behind it, and
// can't build a standing queue for itself either.
//
// Enqueue never blocks. Dequeue blocks until there's something to send,
// so exactly one goroutine — the connection's writer — should call it.
type Scheduler struct {
	mu   sync.Mutex
	cond *sync.Cond
	cfg  Config
	now  func() time.Time

	flows    map[FlowKey]*flow
	newFlows list.List
	oldFlows list.List
	total    int
	closed   bool
	stats    Stats
}

type packet struct {
	data []byte
	enq  time.Time
}

type flow struct {
	key     FlowKey
	q       []packet
	bytes   int
	deficit int
	elem    *list.Element // position in newFlows/oldFlows; nil while idle
	inNew   bool
	codel   codelState
}

type codelState struct {
	firstAboveTime time.Time
	dropNext       time.Time
	count          uint32
	lastCount      uint32
	dropping       bool
}

// New creates a Scheduler; zero fields in cfg take the defaults.
func New(cfg Config) *Scheduler {
	if cfg.Quantum <= 0 {
		cfg.Quantum = defaultQuantum
	}
	if cfg.LimitBytes <= 0 {
		cfg.LimitBytes = defaultLimitBytes
	}
	if cfg.Target <= 0 {
		cfg.Target = defaultTarget
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	s := &Scheduler{cfg: cfg, now: time.Now, flows: make(map[FlowKey]*flow)}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Enqueue adds data to key's flow queue. The scheduler takes ownership
// of data. Never blocks; if the total queue exceeds LimitBytes, packets
// are dropped from the head of the longest flow queue until it doesn't
// (RFC 8290 §4.1) — the flow hogging the queue pays, not whoever
// happened to arrive last.
func (s *Scheduler) Enqueue(key FlowKey, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	f := s.flows[key]
	if f == nil {
		f = &flow{key: key}
		s.flows[key] = f
	}
	f.q = append(f.q, packet{data: data, enq: s.now()})
	f.bytes += len(data)
	s.total += len(data)
	s.stats.Enqueued++
	if f.elem == nil {
		f.deficit = s.cfg.Quantum
		f.elem = s.newFlows.PushBack(f)
		f.inNew = true
	}
	for s.total > s.cfg.LimitBytes && s.dropFromFattest() {
	}
	s.cond.Signal()
}

// Dequeue blocks until a packet is ready to send and returns it, or
// returns ok=false once the scheduler is closed.
func (s *Scheduler) Dequeue() (data []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.closed {
			return nil, false
		}
		if data, ok := s.dequeueLocked(); ok {
			return data, true
		}
		s.cond.Wait()
	}
}

// Close wakes any blocked Dequeue and makes every later call a no-op.
// Anything still queued is discarded — the connection it was headed for
// is gone.
func (s *Scheduler) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

// Stats returns a snapshot of the counters.
func (s *Scheduler) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.QueuedBytes = s.total
	st.ActiveFlows = len(s.flows)
	return st
}

// dequeueLocked is one FQ-CoDel dequeue (RFC 8290 §4.2): serve new
// flows before old ones, round-robin within each list by deficit.
func (s *Scheduler) dequeueLocked() ([]byte, bool) {
	for {
		var lst *list.List
		switch {
		case s.newFlows.Len() > 0:
			lst = &s.newFlows
		case s.oldFlows.Len() > 0:
			lst = &s.oldFlows
		default:
			return nil, false
		}
		f := lst.Front().Value.(*flow)

		if f.deficit <= 0 {
			f.deficit += s.cfg.Quantum
			s.moveToOld(f)
			continue
		}

		data, ok := s.codelDequeue(f)
		if !ok {
			// Empty (or CoDel just dropped the rest). A new flow goes to
			// the back of the old list rather than straight out, so a
			// flow can't keep itself "new" forever by draining in short
			// bursts and starve the old list; an old flow is done.
			if f.inNew && s.oldFlows.Len() > 0 {
				s.moveToOld(f)
			} else {
				s.deactivate(f)
			}
			continue
		}
		f.deficit -= len(data)
		s.stats.Dequeued++
		return data, true
	}
}

func (s *Scheduler) moveToOld(f *flow) {
	s.unlink(f)
	f.elem = s.oldFlows.PushBack(f)
	f.inNew = false
}

// deactivate forgets an idle flow entirely, so the map only ever holds
// flows with something queued — its next packet re-enters as a new
// (sparse) flow, which is exactly the priority an intermittent flow
// should get.
func (s *Scheduler) deactivate(f *flow) {
	s.unlink(f)
	f.elem = nil
	delete(s.flows, f.key)
}

func (s *Scheduler) unlink(f *flow) {
	if f.inNew {
		s.newFlows.Remove(f.elem)
	} else {
		s.oldFlows.Remove(f.elem)
	}
}

func (s *Scheduler) popHead(f *flow) packet {
	p := f.q[0]
	f.q[0] = packet{}
	f.q = f.q[1:]
	f.bytes -= len(p.data)
	s.total -= len(p.data)
	return p
}

// dropFromFattest drops the head packet of the flow with the most bytes
// queued. Reports false if there was nothing to drop.
func (s *Scheduler) dropFromFattest() bool {
	var fat *flow
	for _, f := range s.flows {
		if len(f.q) > 0 && (fat == nil || f.bytes > fat.bytes) {
			fat = f
		}
	}
	if fat == nil {
		return false
	}
	s.popHead(fat)
	s.stats.OverflowDrops++
	return true
}

// doDequeue is CoDel's dodequeue: pop the head and report whether the
// queue has now been above Target for a full Interval.
func (s *Scheduler) doDequeue(f *flow, now time.Time) (p packet, have, okToDrop bool) {
	c := &f.codel
	if len(f.q) == 0 {
		c.firstAboveTime = time.Time{}
		return packet{}, false, false
	}
	p = s.popHead(f)
	if now.Sub(p.enq) < s.cfg.Target || f.bytes <= maxPacket {
		c.firstAboveTime = time.Time{}
	} else if c.firstAboveTime.IsZero() {
		c.firstAboveTime = now.Add(s.cfg.Interval)
	} else if !now.Before(c.firstAboveTime) {
		okToDrop = true
	}
	return p, true, okToDrop
}

// codelDequeue is CoDel's dequeue (RFC 8289 §5.5, the Linux variant of
// the drop-state re-entry): returns the next packet worth sending from
// f, dropping ahead of it as the control law dictates.
func (s *Scheduler) codelDequeue(f *flow) ([]byte, bool) {
	now := s.now()
	c := &f.codel
	p, have, okToDrop := s.doDequeue(f, now)

	if c.dropping {
		if !okToDrop {
			c.dropping = false
		}
		for c.dropping && !now.Before(c.dropNext) {
			s.stats.CodelDrops++
			c.count++
			p, have, okToDrop = s.doDequeue(f, now)
			if !okToDrop {
				c.dropping = false
			} else {
				c.dropNext = controlLaw(c.dropNext, c.count, s.cfg.Interval)
			}
		}
	} else if okToDrop {
		s.stats.CodelDrops++
		p, have, _ = s.doDequeue(f, now)
		c.dropping = true
		delta := c.count - c.lastCount
		c.count = 1
		if delta > 1 && now.Sub(c.dropNext) < 16*s.cfg.Interval {
			c.count = delta
		}
		c.dropNext = controlLaw(now, c.count, s.cfg.Interval)
		c.lastCount = c.count
	}

	if !have {
		return nil, false
	}
	return p.data, true
}

// controlLaw spaces successive drops at Interval/sqrt(count) — gently at
// first, then harder the longer the queue refuses to drain.
func controlLaw(t time.Time, count uint32, interval time.Duration) time.Time {
	return t.Add(time.Duration(float64(interval) / math.Sqrt(float64(count))))
}
