package sched

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PathWriter owns the writes to one connection of a multipath set.
//
// Multipath only helps if a stalled path (a retransmit, a zero window)
// can't hold up the healthy ones — but writing a duplicated frame to
// every path in turn from one goroutine does exactly that: the first
// blocked Write stalls every copy behind it. A PathWriter gives each path
// its own goroutine and a small queue, and Send never blocks.
type PathWriter struct {
	conn      net.Conn
	ch        chan queued
	maxAge    time.Duration
	done      chan struct{}
	closeOnce sync.Once
	drops     atomic.Uint64
}

type queued struct {
	data []byte
	t    time.Time
}

// NewPathWriter starts a writer for conn holding up to depth pending
// frames. Frames that sat in the queue longer than maxAge are skipped
// instead of written (0 = never): the receiver would discard them as
// stale anyway, and bursting them out right as a path recovers only
// delays the fresh ones behind them.
func NewPathWriter(conn net.Conn, depth int, maxAge time.Duration) *PathWriter {
	if depth < 1 {
		depth = 1
	}
	p := &PathWriter{
		conn:   conn,
		ch:     make(chan queued, depth),
		maxAge: maxAge,
		done:   make(chan struct{}),
	}
	go p.run()
	return p
}

// Send queues data for this path without ever blocking. If the path is
// backed up, the oldest queued frame is discarded to make room — for
// real-time traffic the newest data is what matters, and the other
// paths carry their own copy of whatever gets dropped here. data must
// not be modified afterwards; the same slice may be handed to several
// PathWriters.
func (p *PathWriter) Send(data []byte) {
	q := queued{data: data, t: time.Now()}
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-p.done:
			return
		case p.ch <- q:
			return
		default:
		}
		select {
		case <-p.ch:
			p.drops.Add(1)
		default:
		}
	}
	p.drops.Add(1) // lost the race to other senders three times; drop this one
}

// Drops reports how many frames this path discarded (queue overflow or
// staleness).
func (p *PathWriter) Drops() uint64 { return p.drops.Load() }

// Close stops the writer and closes the connection, so whoever reads
// from it notices and cleans up. Safe to call more than once.
func (p *PathWriter) Close() {
	p.closeOnce.Do(func() {
		close(p.done)
		p.conn.Close()
	})
}

func (p *PathWriter) run() {
	for {
		select {
		case <-p.done:
			return
		case q := <-p.ch:
			if p.maxAge > 0 && time.Since(q.t) > p.maxAge {
				p.drops.Add(1)
				continue
			}
			if _, err := p.conn.Write(q.data); err != nil {
				p.Close()
				return
			}
		}
	}
}
