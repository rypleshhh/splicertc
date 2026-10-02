package sched

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PathWriter writes to one connection of a multipath set in its own
// goroutine, so a slow path doesn't block the others.
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

// NewPathWriter starts a writer with a queue of depth frames. Frames
// older than maxAge are skipped (0 = no limit).
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

// Send never blocks. If the queue is full the oldest frame is dropped,
// other paths still have their copy. Don't modify data after Send.
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
	p.drops.Add(1)
}

func (p *PathWriter) Drops() uint64 { return p.drops.Load() }

// Close stops the writer and closes the connection.
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
