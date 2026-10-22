// Package frame is the wire format for the droppable/glue channels.
// Every frame has a sequence number and a send timestamp, so the
// receiver can drop frames that arrived too late or were already
// superseded by a newer one.
//
// TCP never reorders, but a stalled connection can deliver frames late.
// Here late frames get dropped instead of being delivered.
package frame

import (
	"encoding/binary"
	"io"
	"time"
)

const headerSize = 4 + 8 + 2 // seq + timestamp ms + payload length

// MaxPayload is the biggest payload a frame can carry (the length field
// is 16 bit).
const MaxPayload = 65535

type Frame struct {
	Seq         uint32
	TimestampMS int64
	Payload     []byte
}

// New creates a frame with the current time.
func New(seq uint32, payload []byte) Frame {
	return Frame{Seq: seq, TimestampMS: time.Now().UnixMilli(), Payload: payload}
}

// Marshal returns the frame as bytes, or nil if the payload is bigger
// than MaxPayload: the 16 bit length would wrap around and the receiver
// would read the rest of the stream shifted. Writing nil sends nothing,
// so an oversized frame is just dropped.
func (f Frame) Marshal() []byte {
	if len(f.Payload) > MaxPayload {
		return nil
	}
	buf := make([]byte, headerSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.Seq)
	binary.BigEndian.PutUint64(buf[4:12], uint64(f.TimestampMS))
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(f.Payload)))
	copy(buf[headerSize:], f.Payload)
	return buf
}

func ReadFrame(r io.Reader) (Frame, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	seq := binary.BigEndian.Uint32(header[0:4])
	ts := int64(binary.BigEndian.Uint64(header[4:12]))
	n := binary.BigEndian.Uint16(header[12:14])

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Seq: seq, TimestampMS: ts, Payload: payload}, nil
}

// Receiver decides if an incoming frame should still be delivered: not
// a duplicate (multipath sends every frame several times) and not too
// late compared to the best delay seen.
type Receiver struct {
	maxAge time.Duration
	now    func() time.Time // time.Now, replaced in tests

	// Duplicates are found with a window of the last seqWindow sequence
	// numbers (like IPsec anti-replay, RFC 4303): a frame that arrives
	// out of order but wasn't seen yet is still delivered.
	haveTop bool
	top     uint32 // highest seq accepted so far
	seen    [seqWindow / 64]uint64

	// Client and server clocks are not in sync, so recv-send time includes
	// the clock difference. We keep the minimum (recv-send) seen and count
	// the age from that, not from zero. Two windows so the minimum can
	// slowly follow clock drift.
	haveOffset    bool
	prevMinOffset time.Duration
	curMinOffset  time.Duration
	windowStart   time.Time
	// first frame of the current run of late frames, zero if the last
	// frame was on time
	lateSince time.Time
}

const (
	offsetWindow = 5 * time.Second
	seqWindow    = 1024
	// If every frame is late for this long, the delay itself has grown
	// (new route): take the current delay as the new baseline instead of
	// dropping everything until the minimum window rolls over.
	rebaselineAfter = time.Second
)

// NewReceiver drops frames that are more than maxAge late compared to
// the best delay seen so far.
func NewReceiver(maxAge time.Duration) *Receiver {
	return &Receiver{maxAge: maxAge, now: time.Now}
}

// Accept reports if f should be delivered. The first frame is always
// accepted since there's nothing to compare it with yet.
func (r *Receiver) Accept(f Frame) (deliver bool, reason string) {
	now := r.now()
	raw := now.Sub(time.UnixMilli(f.TimestampMS))

	switch {
	case !r.haveOffset:
		r.haveOffset = true
		r.curMinOffset, r.prevMinOffset = raw, raw
		r.windowStart = now
	case raw < r.curMinOffset:
		r.curMinOffset = raw
	}
	if now.Sub(r.windowStart) >= offsetWindow {
		r.prevMinOffset, r.curMinOffset = r.curMinOffset, raw
		r.windowStart = now
	}

	baseline := min(r.prevMinOffset, r.curMinOffset)
	if raw-baseline > r.maxAge {
		if r.lateSince.IsZero() {
			r.lateSince = now
		}
		if now.Sub(r.lateSince) < rebaselineAfter {
			return false, "ttl exceeded"
		}
		r.prevMinOffset, r.curMinOffset = raw, raw
		r.windowStart = now
	}
	r.lateSince = time.Time{}
	return r.AcceptSeq(f)
}

// AcceptSeq only checks for duplicates, not age. Used for ping frames,
// where we want to see late replies too.
//
// seq is uint32 and wraps around after 4294967295 -> 0, so distances are
// computed as int32 (RFC 1982), like TCP does.
func (r *Receiver) AcceptSeq(f Frame) (deliver bool, reason string) {
	if !r.haveTop {
		r.haveTop = true
		r.top = f.Seq
		r.mark(f.Seq)
		return true, ""
	}
	d := int32(f.Seq - r.top)
	switch {
	case d > 0:
		// newer than everything: slide the window, forget what fell out
		if d >= seqWindow {
			r.seen = [seqWindow / 64]uint64{}
		} else {
			for i := uint32(1); i <= uint32(d); i++ {
				r.unmark(r.top + i)
			}
		}
		r.top = f.Seq
		r.mark(f.Seq)
		return true, ""
	case -d >= seqWindow:
		return false, "too old"
	case r.marked(f.Seq):
		return false, "duplicate"
	default:
		r.mark(f.Seq) // arrived out of order, but it's new
		return true, ""
	}
}

func (r *Receiver) mark(seq uint32)   { r.seen[seq%seqWindow/64] |= 1 << (seq % 64) }
func (r *Receiver) unmark(seq uint32) { r.seen[seq%seqWindow/64] &^= 1 << (seq % 64) }
func (r *Receiver) marked(seq uint32) bool {
	return r.seen[seq%seqWindow/64]&(1<<(seq%64)) != 0
}
