// Package frame implements the droppable channel's own wire format and
// the receiver-side staleness logic described in the brief: each frame
// carries a sequence number and send timestamp; a frame that arrives
// too late (older than maxAge) or that's been superseded by a newer
// sequence number already delivered gets dropped instead of queued —
// the whole point of this channel existing separately from the
// reliable/smux one.
//
// Note: over a single TCP/TLS connection, frames can never actually
// arrive out of order — TCP guarantees that. What this logic protects
// against is a frame that's *stale by the time it's read*, because the
// connection stalled (retransmit, congestion) while it was in flight.
// TCP hides packet loss as added latency; this is where that latency
// gets turned into an explicit drop instead of being delivered late.
package frame

import (
	"encoding/binary"
	"io"
	"time"
)

const headerSize = 4 + 8 + 2 // seq(4) + timestampMS(8) + payloadLen(2)

// Frame is one unit sent over the droppable channel.
type Frame struct {
	Seq         uint32
	TimestampMS int64
	Payload     []byte
}

// New builds a frame stamped with the current time.
func New(seq uint32, payload []byte) Frame {
	return Frame{Seq: seq, TimestampMS: time.Now().UnixMilli(), Payload: payload}
}

// Marshal encodes the frame for the wire.
func (f Frame) Marshal() []byte {
	buf := make([]byte, headerSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.Seq)
	binary.BigEndian.PutUint64(buf[4:12], uint64(f.TimestampMS))
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(f.Payload)))
	copy(buf[headerSize:], f.Payload)
	return buf
}

// ReadFrame reads one frame from r. Blocks until a full frame arrives
// or the connection errors/closes.
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

// Receiver holds the delivery state for one droppable stream and decides
// whether each incoming frame is still worth delivering.
type Receiver struct {
	maxAge      time.Duration
	lastSeq     uint32
	haveLastSeq bool
}

// NewReceiver creates a receiver that drops any frame older than maxAge
// by the time it's evaluated.
func NewReceiver(maxAge time.Duration) *Receiver {
	return &Receiver{maxAge: maxAge}
}

// Accept reports whether f should be delivered to the application, and
// updates internal state if so. Call this exactly once per frame, in
// the order frames were read.
func (r *Receiver) Accept(f Frame) (deliver bool, reason string) {
	age := time.Since(time.UnixMilli(f.TimestampMS))
	if age > r.maxAge {
		return false, "ttl exceeded"
	}
	if r.haveLastSeq && f.Seq <= r.lastSeq {
		return false, "superseded"
	}
	r.lastSeq = f.Seq
	r.haveLastSeq = true
	return true, ""
}
