package main

import (
	"sync"
	"time"
)

// flowInfo keeps the addresses of the original packet so we can build
// the reply packet.
type flowInfo struct {
	origSrc, origDst         [4]byte
	origSrcPort, origDstPort uint16
}

// flowKey is the full 4-tuple. Source port alone isn't enough, Steam
// talks to many relays from one socket.
type flowKey struct {
	srcPort uint16
	dst     [4]byte
	dstPort uint16
}

func flowKeyOf(fi flowInfo) flowKey {
	return flowKey{srcPort: fi.origSrcPort, dst: fi.origDst, dstPort: fi.origDstPort}
}

type flowEntry struct {
	info     flowInfo
	lastSeen time.Time
}

// flowTable gives glue flow IDs to 4-tuples. IDs are uint16, so after
// 65536 flows they wrap around; free IDs are reused, IDs still in use
// are skipped. The server rebinds a flow ID if its destination changes.
type flowTable struct {
	mu    sync.Mutex
	ids   map[flowKey]uint16
	flows map[uint16]*flowEntry
	next  uint16
}

func newFlowTable() *flowTable {
	return &flowTable{ids: make(map[flowKey]uint16), flows: make(map[uint16]*flowEntry)}
}

// id returns the flow ID for fi, giving it a new one if needed. ok is
// false only if all 65536 IDs are in use.
func (t *flowTable) id(fi flowInfo, now time.Time) (id uint16, ok bool) {
	key := flowKeyOf(fi)
	t.mu.Lock()
	defer t.mu.Unlock()
	if id, ok := t.ids[key]; ok {
		t.flows[id].lastSeen = now
		return id, true
	}
	for i := 0; i < 1<<16; i++ {
		t.next++
		if _, used := t.flows[t.next]; used {
			continue
		}
		t.ids[key] = t.next
		t.flows[t.next] = &flowEntry{info: fi, lastSeen: now}
		return t.next, true
	}
	return 0, false
}

// lookup is used for replies. A reply also counts as activity.
func (t *flowTable) lookup(id uint16, now time.Time) (flowInfo, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.flows[id]
	if !ok {
		return flowInfo{}, false
	}
	e.lastSeen = now
	return e.info, true
}

// sweep removes flows idle for longer than idle, returns how many.
func (t *flowTable) sweep(now time.Time, idle time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for id, e := range t.flows {
		if now.Sub(e.lastSeen) > idle {
			delete(t.flows, id)
			delete(t.ids, flowKeyOf(e.info))
			n++
		}
	}
	return n
}

func (t *flowTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}
