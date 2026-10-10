package main

import (
	"sync"
	"time"
)

// udpRouter decides once per UDP flow if it goes over glue or vpn, and
// then keeps that decision. Moving a flow from one channel to the other
// changes its source address on the internet side, and the game server
// sees that as a new client.
type udpRouter struct {
	// owner returns the process name for a local UDP port.
	owner func(port uint16) (name string, ok bool)
	// refresh reloads the port table (rate limited by the caller).
	refresh func()
	isGame  func(name string) bool

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

func newUDPRouter(owner func(uint16) (string, bool), refresh func(), isGame func(string) bool) *udpRouter {
	return &udpRouter{
		owner:       owner,
		refresh:     refresh,
		isGame:      isGame,
		unknownWait: time.Second,
		routes:      make(map[flowKey]*route),
	}
}

// classify returns where the packet goes. send=false means drop it: the
// socket owner is not known yet, and it's better to lose a packet than
// to start the flow on the wrong channel.
func (r *udpRouter) classify(key flowKey, now time.Time) (glue, send bool) {
	r.mu.Lock()
	rt, ok := r.routes[key]
	if ok && rt.decided {
		rt.lastSeen = now
		r.mu.Unlock()
		return rt.glue, true
	}
	if !ok {
		rt = &route{first: now}
		r.routes[key] = rt
	}
	rt.lastSeen = now
	r.mu.Unlock()

	name, found := r.owner(key.srcPort)
	if !found {
		r.refresh()
		name, found = r.owner(key.srcPort)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case found:
		rt.decided = true
		rt.glue = r.isGame(name)
	case now.Sub(rt.first) >= r.unknownWait:
		rt.decided = true // never showed up, vpn is the safe choice
	default:
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
