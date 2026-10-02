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

type Frame struct {
	Seq         uint32
	TimestampMS int64
	Payload     []byte
}

// New creates a frame with the current time.
func New(seq uint32, payload []byte) Frame {
	return Frame{Seq: seq, TimestampMS: time.Now().UnixMilli(), Payload: payload}
}

func (f Frame) Marshal() []byte {
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

// Receiver decides if an incoming frame should still be delivered.
type Receiver struct {
	maxAge      time.Duration
	lastSeq     uint32
	haveLastSeq bool

	// Client and server clocks are not in sync, so recv-send time includes
	// the clock difference. We keep the minimum (recv-send) seen and count
	// the age from that, not from zero. Two windows so the minimum can
	// slowly follow clock drift.
	haveOffset    bool
	prevMinOffset time.Duration
	curMinOffset  time.Duration
	windowStart   time.Time
}

const offsetWindow = 5 * time.Second

// NewReceiver drops frames that are more than maxAge late compared to
// the best delay seen so far.
func NewReceiver(maxAge time.Duration) *Receiver {
	return &Receiver{maxAge: maxAge}
}

// Accept reports if f should be delivered. Call it once per frame, in
// the order frames were read. The first frame is always accepted since
// there's nothing to compare it with yet.
func (r *Receiver) Accept(f Frame) (deliver bool, reason string) {
	now := time.Now()
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

	baseline := r.prevMinOffset
	if r.curMinOffset < baseline {
		baseline = r.curMinOffset
	}

	if age := raw - baseline; age > r.maxAge {
		return false, "ttl exceeded"
	}
	return r.AcceptSeq(f)
}

// AcceptSeq only checks for duplicates, not age. Used for ping frames,
// where we want to see late replies too.
func (r *Receiver) AcceptSeq(f Frame) (deliver bool, reason string) {
	if r.haveLastSeq && f.Seq <= r.lastSeq {
		return false, "superseded"
	}
	r.lastSeq = f.Seq
	r.haveLastSeq = true
	return true, ""
}
