package sched

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// Config tunes a Scheduler. Zero fields use the defaults below
// (same as Linux fq_codel, except a smaller byte limit).
type Config struct {
	Quantum    int
	LimitBytes int
	Target     time.Duration
	Interval   time.Duration
}

const (
	defaultQuantum    = 1514
	defaultLimitBytes = 2 << 20
	defaultTarget     = 5 * time.Millisecond
	defaultInterval   = 100 * time.Millisecond

	// CoDel never drops when only about one packet is queued.
	maxPacket = 1514
)

type Stats struct {
	Enqueued, Dequeued        uint64
	CodelDrops, OverflowDrops uint64
	QueuedBytes, ActiveFlows  int
}

// Scheduler is FQ-CoDel (RFC 8290): one queue per flow, deficit round
// robin between them, new flows served before old ones, and CoDel
// (RFC 8289) on every flow queue. A download can't make small packets
// of other flows wait behind it.
//
// Enqueue never blocks. Dequeue blocks, only one goroutine should call it.
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
	elem    *list.Element // nil when the flow is idle
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

// Enqueue adds data to the flow's queue. If the total goes over the
// limit, packets are dropped from the biggest flow.
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

// Dequeue waits for the next packet. Returns false after Close.
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

func (s *Scheduler) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

func (s *Scheduler) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.QueuedBytes = s.total
	st.ActiveFlows = len(s.flows)
	return st
}

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
			// Empty new flow goes to the old list first so it can't stay
			// "new" forever and starve the others.
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

// deactivate removes an idle flow. Its next packet makes it a new flow again.
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

// doDequeue is dodequeue() from RFC 8289.
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

// codelDequeue is dequeue() from RFC 8289 (Linux variant).
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

func controlLaw(t time.Time, count uint32, interval time.Duration) time.Time {
	return t.Add(time.Duration(float64(interval) / math.Sqrt(float64(count))))
}
