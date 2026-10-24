package main

import (
	"sync"
	"time"

	"tcp-dormtun/internal/pktfilter"
)

// udpRouter decides once per UDP flow if it goes over glue or vpn, and
// then keeps that decision. Moving a flow from one channel to the other
// changes its source address on the internet side, and the game server
// sees that as a new client.
type udpRouter struct {
	// owner returns the process name for a local UDP port.
	owner func(port uint16) (name string, ok bool)
	// requestRefresh asks for the port table to be reloaded in the
	// background. It must not block: classify runs in the TUN read loop.
	requestRefresh func()
	isGame         func(name string) bool

	// how long to wait for an unknown port to show up in the table
	// before giving up and sending the flow over vpn
	unknownWait time.Duration

	mu     sync.Mutex
	routes map[flowKey]*route
}

type route struct {
	decided  bool
	glue     bool
	first    time.Time
	lastSeen time.Time
}

func newUDPRouter(owner func(uint16) (string, bool), requestRefresh func(), isGame func(string) bool) *udpRouter {
	return &udpRouter{
		owner:          owner,
		requestRefresh: requestRefresh,
		isGame:         isGame,
		unknownWait:    time.Second,
		routes:         make(map[flowKey]*route),
	}
}

// classify returns where the packet goes. send=false means drop it: the
// socket owner is not known yet, and it's better to lose a packet than
// to start the flow on the wrong channel.
func (r *udpRouter) classify(key flowKey, now time.Time) (glue, send bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, ok := r.routes[key]
	if !ok {
		rt = &route{first: now}
		r.routes[key] = rt
	}
	rt.lastSeen = now
	if rt.decided {
		return rt.glue, true
	}

	name, found := r.owner(key.srcPort)
	switch {
	case found:
		rt.decided = true
		rt.glue = r.isGame(name)
	case now.Sub(rt.first) >= r.unknownWait:
		rt.decided = true // never showed up, vpn is the safe choice
	default:
		r.requestRefresh()
		return false, false
	}
	return rt.glue, true
}

// sweep forgets flows idle for longer than idle.
func (r *udpRouter) sweep(now time.Time, idle time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, rt := range r.routes {
		if now.Sub(rt.lastSeen) > idle {
			delete(r.routes, k)
		}
	}
}

// refresher runs fn in its own goroutine when kicked, then waits gap
// before it can run again. kick never blocks; kicks that come while fn
// runs or waits are merged into one more run.
type refresher struct {
	kicks chan struct{}
}

func startRefresher(fn func(), gap time.Duration) *refresher {
	r := &refresher{kicks: make(chan struct{}, 1)}
	go func() {
		for range r.kicks {
			fn()
			time.Sleep(gap)
		}
	}()
	return r
}

func (r *refresher) kick() {
	select {
	case r.kicks <- struct{}{}:
	default:
	}
}

// packetAction is what the vpn read loop does with one packet.
type packetAction int

const (
	toVPN packetAction = iota
	toGlue
	dropUnknown  // socket owner not known yet, or no free flow ID
	dropFragment // UDP fragment to a destination that has glue flows
)

// gameSplit picks the channel for each packet when game_processes is set.
type gameSplit struct {
	router *udpRouter
	flows  *flowTable
}

// decide returns the action and, for toGlue, the glue flow ID.
func (s *gameSplit) decide(info pktfilter.Info, now time.Time) (packetAction, uint16) {
	if info.Proto != 17 {
		return toVPN, 0
	}
	if info.Fragment {
		// Glue carries UDP payloads, not IP fragments. Over vpn the
		// fragment would reach the game server from another address
		// than the rest of the flow, so it's dropped; the datagram is
		// lost either way.
		var dst [4]byte
		copy(dst[:], info.Dst.To4())
		if s.flows.hasDst(dst) {
			return dropFragment, 0
		}
		return toVPN, 0
	}
	if info.Payload == nil {
		return toVPN, 0 // broken UDP header, not a game packet
	}

	fi := flowInfo{origSrcPort: info.SrcPort, origDstPort: info.DstPort}
	copy(fi.origSrc[:], info.Src.To4())
	copy(fi.origDst[:], info.Dst.To4())
	glue, send := s.router.classify(flowKeyOf(fi), now)
	switch {
	case !send:
		return dropUnknown, 0
	case !glue:
		return toVPN, 0
	}
	id, ok := s.flows.id(fi, now)
	if !ok {
		return dropUnknown, 0 // all flow IDs in use
	}
	return toGlue, id
}
