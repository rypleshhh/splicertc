package main

import (
	"crypto/rand"
	"fmt"
	"io"
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
	// onFrame gets every frame from the server except path pings, with
	// the epoch of the server session its path joined. It's called from
	// several goroutines at once.
	onFrame func(epoch uint64, f frame.Frame)
	// onEpoch gets the epoch of every newly connected path before any of
	// its frames, can be nil
	onEpoch func(epoch uint64)
	// onFatal gets errors that reconnecting won't fix (wrong key or
	// certificate). The path stops; the caller should shut down.
	onFatal func(error)

	// can be replaced in tests
	dial func() (net.Conn, uint64, error)

	mu      sync.Mutex
	writers map[int]*sched.PathWriter
}

// startGluePaths dials n paths. It fails only if none of them could
// connect; paths that failed are dialed again in the background.
func startGluePaths(srv endpoint, key []byte, n int, replies *replyHandler, onFatal func(error)) (*gluePaths, error) {
	g := newGluePaths(srv, key, replies.handle, onFatal)
	g.onEpoch = replies.setEpoch
	return g, g.start(n)
}

func newGluePaths(srv endpoint, key []byte, onFrame func(uint64, frame.Frame), onFatal func(error)) *gluePaths {
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

// dialServer connects one path: TLS, auth, hello. It returns the epoch
// of the server session the path joined.
func (g *gluePaths) dialServer() (net.Conn, uint64, error) {
	c, err := transport.Dial(g.srv.addr, g.srv.dc)
	if err != nil {
		return nil, 0, err
	}
	_ = c.SetDeadline(time.Now().Add(transport.DialTimeout))
	if err := auth.ClientHandshake(c, g.key); err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("auth: %w", err)
	}
	epoch, err := joinSession(c, g.sid)
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	_ = c.SetDeadline(time.Time{})
	transport.SetSendBuffer(c, glueSendBuffer)
	return c, epoch, nil
}

// joinSession sends the hello and reads the server's accept.
func joinSession(c net.Conn, sid []byte) (epoch uint64, err error) {
	if _, err := c.Write(glue.EncodeHello(sid)); err != nil {
		return 0, fmt.Errorf("send hello: %w", err)
	}
	accept := make([]byte, glue.AcceptSize)
	if _, err := io.ReadFull(c, accept); err != nil {
		// a server older than the client reads the hello as a session ID
		// and never answers
		return 0, fmt.Errorf("no accept from the server (older server version?): %w", err)
	}
	return glue.DecodeAccept(accept)
}

// keepPath keeps path i connected. It stops only on a permanent dial
// error, which goes to onFatal. The result of the first attempt goes to
// first.
func (g *gluePaths) keepPath(i int, first chan<- error) {
	backoff := redialMin
	for {
		c, epoch, err := g.dial()
		var w *sched.PathWriter
		if err == nil {
			if g.onEpoch != nil {
				g.onEpoch(epoch)
			}
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
		reason := g.servePath(i, c, w, epoch)
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
func (g *gluePaths) servePath(i int, c net.Conn, w *sched.PathWriter, epoch uint64) string {
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
			g.onFrame(epoch, f)
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

const replyMaxAge = 150 * time.Millisecond

// replyHandler takes replies from all paths: duplicates are dropped, the
// rest is written into the TUN.
type replyHandler struct {
	flows    *flowTable
	devWrite func([]byte)
	onPing   func(nonce uint64) // can be nil

	mu    sync.Mutex
	epoch uint64
	recv  *frame.Receiver
}

func newReplyHandler(flows *flowTable, devWrite func([]byte), onPing func(nonce uint64)) *replyHandler {
	return &replyHandler{flows: flows, devWrite: devWrite, onPing: onPing, recv: frame.NewReceiver(replyMaxAge)}
}

// setEpoch is called for every path that connects. A new epoch is a new
// server session whose seq starts from zero; the old dedup window would
// drop its replies as "too old" until seq caught up. The latest path
// wins: paths of the old session are dead anyway (a session is replaced
// only after it lost all paths or the server restarted).
func (h *replyHandler) setEpoch(epoch uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if epoch == h.epoch {
		return
	}
	if h.epoch != 0 {
		log.Printf("glue: new server session (epoch %x), reply sequence restarts", epoch)
	}
	h.epoch = epoch
	h.recv = frame.NewReceiver(replyMaxAge)
}

func (h *replyHandler) handle(epoch uint64, f frame.Frame) {
	// ping reply, stats ignores duplicates
	if nonce, isPing := glue.DecodePing(f.Payload); isPing {
		if h.onPing != nil {
			h.onPing(nonce)
		}
		return
	}
	h.mu.Lock()
	ok := epoch == h.epoch
	if ok {
		ok, _ = h.recv.Accept(f)
	}
	h.mu.Unlock()
	if !ok {
		return // old session, duplicate or too old
	}
	flowID, payload, err := glue.DecodeInbound(f.Payload)
	if err != nil {
		return
	}
	fi, known := h.flows.lookup(flowID, time.Now())
	if !known {
		return
	}
	if pkt := pktfilter.BuildIPv4UDP(fi.origDst, fi.origSrc, fi.origDstPort, fi.origSrcPort, payload); pkt != nil {
		h.devWrite(pkt)
	}
}

// live returns how many paths are connected right now.
func (g *gluePaths) live() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.writers)
}
