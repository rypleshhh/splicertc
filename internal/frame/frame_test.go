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

// Staleness is measured from the baseline built by earlier frames.
func TestDropsStaleByTTL(t *testing.T) {
	r := NewReceiver(50 * time.Millisecond)

	// on-time frames to build the baseline
	for i := uint32(1); i <= 3; i++ {
		f := New(i, []byte("on time"))
		if ok, reason := r.Accept(f); !ok {
			t.Fatalf("frame %d: expected baseline frame to be accepted, got reason=%q", i, reason)
		}
	}

	// 200ms later than the baseline -> dropped
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

// Sender clock is 300ms off (more than the 150ms TTL), nothing should
// be dropped because of that.
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
			t.Fatalf("frame %d: dropped despite only constant clock skew (no real delay), reason=%q", i, reason)
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
