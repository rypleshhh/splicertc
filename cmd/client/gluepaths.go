package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/pktfilter"
	"tcp-dormtun/internal/sched"
	"tcp-dormtun/internal/transport"
)

// Queue size per glue path (~0.5s of game traffic). Older frames would
// be dropped by the server anyway (150ms TTL).
const (
	gluePathDepth  = 32
	glueStaleAfter = 150 * time.Millisecond
)

// Every path is pinged on its own. A path that didn't answer for
// pathDeadAfter is closed and dialed again, the other paths keep working.
const (
	pathPingInterval = 200 * time.Millisecond
	pathDeadAfter    = time.Second
	// small send buffer: game traffic is tiny, and with a big buffer a
	// stuck path keeps old packets instead of failing fast
	glueSendBuffer = 32 * 1024
	redialMin      = 500 * time.Millisecond
	redialMax      = 5 * time.Second
)

// gluePaths keeps N connections to the glue server with the same session
// ID. Frames are sent on all of them, the server drops the duplicates.
type gluePaths struct {
	srv endpoint
	key []byte
	sid []byte
	// onFrame gets every frame from the server except path pings. It's
	// called from several goroutines at once.
	onFrame func(frame.Frame)
	// onFatal gets errors that reconnecting won't fix (wrong key or
	// certificate). The path stops; the caller should shut down.
	onFatal func(error)

	// can be replaced in tests
	dial func() (net.Conn, error)

	mu      sync.Mutex
	writers map[int]*sched.PathWriter
}

// startGluePaths dials n paths. It fails only if none of them could
// connect; paths that failed are dialed again in the background.
func startGluePaths(srv endpoint, key []byte, n int, onFrame func(frame.Frame), onFatal func(error)) (*gluePaths, error) {
	g := newGluePaths(srv, key, onFrame, onFatal)
	return g, g.start(n)
}

func newGluePaths(srv endpoint, key []byte, onFrame func(frame.Frame), onFatal func(error)) *gluePaths {
	g := &gluePaths{
		srv:     srv,
		key:     key,
		onFrame: onFrame,
		onFatal: onFatal,
		writers: make(map[int]*sched.PathWriter),
	}
	g.dial = g.dialServer
	return g
}

func (g *gluePaths) start(n int) error {
	if n < 1 {
		n = 1
	}
	g.sid = make([]byte, 8)
	if _, err := rand.Read(g.sid); err != nil {
		return fmt.Errorf("generate session id: %w", err)
	}

	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go g.keepPath(i, results)
	}
	var lastErr error
	ok := 0
	for i := 0; i < n; i++ {
		if err := <-results; err != nil {
			lastErr = err
		} else {
			ok++
		}
	}
	if ok == 0 {
		return lastErr
	}
	if ok < n {
		log.Printf("glue: only %d of %d paths connected, the rest will retry", ok, n)
	}
	return nil
}

// dialServer connects one path: TLS, auth, session ID.
func (g *gluePaths) dialServer() (net.Conn, error) {
	c, err := transport.Dial(g.srv.addr, g.srv.dc)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(transport.DialTimeout))
	if err := auth.ClientHandshake(c, g.key); err != nil {
		c.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	if _, err := c.Write(g.sid); err != nil {
		c.Close()
		return nil, fmt.Errorf("send session id: %w", err)
	}
	_ = c.SetDeadline(time.Time{})
	transport.SetSendBuffer(c, glueSendBuffer)
	return c, nil
}

// keepPath keeps path i connected. It stops only on a permanent dial
// error, which goes to onFatal. The result of the first attempt goes to
// first.
func (g *gluePaths) keepPath(i int, first chan<- error) {
	backoff := redialMin
	for {
		c, err := g.dial()
		var w *sched.PathWriter
		if err == nil {
			// registered before reporting, so live() is right after start()
			w = sched.NewPathWriter(c, gluePathDepth, glueStaleAfter)
			g.mu.Lock()
			g.writers[i] = w
			g.mu.Unlock()
		}
		if first != nil {
			first <- err
			first = nil
		}
		if err != nil && isPermanentDialError(err) {
			// retrying would only get this IP banned
			if g.onFatal != nil {
				g.onFatal(fmt.Errorf("glue: path %d: %w", i, err))
			}
			return
		}
		if err != nil {
			log.Printf("glue: path %d: connect failed: %v (retry in %v)", i, err, backoff)
			time.Sleep(backoff)
			backoff = min(backoff*2, redialMax)
			continue
		}

		started := time.Now()
		reason := g.servePath(i, c, w)
		log.Printf("glue: path %d lost: %s, reconnecting", i, reason)
		// a path that worked for a while gets redialed right away
		if time.Since(started) > 10*time.Second {
			backoff = redialMin
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, redialMax)
	}
}

// servePath runs one connected path until it dies.
func (g *gluePaths) servePath(i int, c net.Conn, w *sched.PathWriter) string {
	var lastEcho atomic.Int64
	lastEcho.Store(time.Now().UnixNano())

	readErr := make(chan error, 1)
	go func() {
		for {
			f, err := frame.ReadFrame(c)
			if err != nil {
				readErr <- err
				w.Close()
				return
			}
			if glue.IsPathPing(f.Payload) {
				lastEcho.Store(time.Now().UnixNano())
				continue
			}
			g.onFrame(f)
		}
	}()

	defer func() {
		g.mu.Lock()
		delete(g.writers, i)
		g.mu.Unlock()
		w.Close()
	}()

	t := time.NewTicker(pathPingInterval)
	defer t.Stop()
	for {
		select {
		case err := <-readErr:
			return "read: " + err.Error()
		case <-w.Done():
			select {
			case err := <-readErr:
				return "read: " + err.Error()
			default:
				return "write failed or timed out"
			}
		case now := <-t.C:
			if silent := now.Sub(time.Unix(0, lastEcho.Load())); silent > pathDeadAfter {
				return fmt.Sprintf("no ping reply for %v", silent.Round(time.Millisecond))
			}
			// seq 0: path pings don't go through the server's dedup
			w.Send(frame.New(0, glue.EncodePathPing(uint64(now.UnixNano()))).Marshal())
		}
	}
}

// send writes wire to every live path. With no live paths it's dropped.
func (g *gluePaths) send(wire []byte) {
	g.mu.Lock()
	for _, w := range g.writers {
		w.Send(wire)
	}
	g.mu.Unlock()
}

// glueReplyHandler makes an onFrame func: replies come on every path, so
// duplicates are dropped, the rest is written into the TUN. onPing can
// be nil.
func glueReplyHandler(flows *flowTable, devWrite func([]byte), onPing func(nonce uint64)) func(frame.Frame) {
	recv := frame.NewReceiver(150 * time.Millisecond)
	var mu sync.Mutex
	return func(f frame.Frame) {
		// ping reply, stats ignores duplicates
		if nonce, isPing := glue.DecodePing(f.Payload); isPing {
			if onPing != nil {
				onPing(nonce)
			}
			return
		}
		mu.Lock()
		ok, _ := recv.Accept(f)
		mu.Unlock()
		if !ok {
			return // duplicate or too old
		}
		flowID, payload, err := glue.DecodeInbound(f.Payload)
		if err != nil {
			return
		}
		fi, known := flows.lookup(flowID, time.Now())
		if !known {
			return
		}
		if pkt := pktfilter.BuildIPv4UDP(fi.origDst, fi.origSrc, fi.origDstPort, fi.origSrcPort, payload); pkt != nil {
			devWrite(pkt)
		}
	}
}

// live returns how many paths are connected right now.
func (g *gluePaths) live() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.writers)
}
