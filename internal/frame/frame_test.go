package frame

import (
	"bytes"
	"testing"
	"time"
)

func TestAcceptFreshFrame(t *testing.T) {
	r := NewReceiver(100 * time.Millisecond)
	f := New(1, []byte("hello"))

	ok, reason := r.Accept(f)
	if !ok {
		t.Fatalf("expected fresh frame to be accepted, got reason=%q", reason)
	}
}

// TestDropsStaleByTTL checks staleness *relative to an established
// baseline*, not relative to a lone frame in a vacuum. A single
// artificially-delayed frame with zero prior context can't be
// distinguished from ordinary clock skew (see TestToleratesClockSkew),
// so Accept now always accepts the very first frame it ever sees — the
// old version of this test asserted the opposite and was asserting the
// bug (see IDEAS.md P0 #1: real game frames were being TTL-dropped
// wholesale on any client/server pair with clock skew > maxAge).
func TestDropsStaleByTTL(t *testing.T) {
	r := NewReceiver(50 * time.Millisecond)

	// A few on-time frames establish the baseline (best-case
	// recv-send offset).
	for i := uint32(1); i <= 3; i++ {
		f := New(i, []byte("on time"))
		if ok, reason := r.Accept(f); !ok {
			t.Fatalf("frame %d: expected baseline frame to be accepted, got reason=%q", i, reason)
		}
	}

	// A frame that arrives 200ms late *relative to that baseline* —
	// not relative to the receiver's own clock — must still be dropped.
	late := Frame{
		Seq:         4,
		TimestampMS: time.Now().Add(-200 * time.Millisecond).UnixMilli(),
		Payload:     []byte("late"),
	}
	ok, reason := r.Accept(late)
	if ok {
		t.Fatalf("expected frame stale relative to the baseline to be dropped")
	}
	if reason != "ttl exceeded" {
		t.Fatalf("expected reason 'ttl exceeded', got %q", reason)
	}
}

// TestToleratesClockSkew is the direct regression test for IDEAS.md's
// P0 #1: before this fix, a large constant clock skew between sender
// and receiver (routine between an unsynced Windows client and a VPS)
// made Accept's TTL check compare against raw cross-host time and drop
// essentially everything, even at near-zero real network delay — this
// is exactly what made -tun-measure show 100% loss at a true RTT of
// ~9ms. Replays a stream of frames all stamped as if the sender's clock
// runs 300ms ahead, at realistic 33ms spacing, and asserts none of them
// get TTL-dropped despite the skew being twice the 150ms TTL itself.
func TestToleratesClockSkew(t *testing.T) {
	const skew = 300 * time.Millisecond // sender's clock is 300ms ahead
	r := NewReceiver(150 * time.Millisecond)

	for i := uint32(1); i <= 50; i++ {
		f := Frame{
			Seq:         i,
			TimestampMS: time.Now().Add(skew).UnixMilli(),
			Payload:     []byte("tick"),
		}
		ok, reason := r.Accept(f)
		if !ok {
			t.Fatalf("frame %d: dropped despite only constant clock skew (no real delay), reason=%q — skew compensation isn't working", i, reason)
		}
		time.Sleep(2 * time.Millisecond) // keep the test fast; spacing itself doesn't matter here
	}
}

func TestDropsSupersededSeq(t *testing.T) {
	r := NewReceiver(time.Second)

	f5 := New(5, []byte("newer"))
	if ok, reason := r.Accept(f5); !ok {
		t.Fatalf("expected seq 5 to be accepted, got reason=%q", reason)
	}

	f3 := New(3, []byte("older, arrived late"))
	ok, reason := r.Accept(f3)
	if ok {
		t.Fatalf("expected seq 3 to be dropped as superseded")
	}
	if reason != "superseded" {
		t.Fatalf("expected reason 'superseded', got %q", reason)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	original := New(42, []byte("payload data"))
	wire := original.Marshal()

	// ReadFrame expects an io.Reader; bytes.Reader satisfies that.
	got, err := ReadFrame(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Seq != original.Seq {
		t.Errorf("seq mismatch: got %d want %d", got.Seq, original.Seq)
	}
	if got.TimestampMS != original.TimestampMS {
		t.Errorf("timestamp mismatch: got %d want %d", got.TimestampMS, original.TimestampMS)
	}
	if string(got.Payload) != string(original.Payload) {
		t.Errorf("payload mismatch: got %q want %q", got.Payload, original.Payload)
	}
}
