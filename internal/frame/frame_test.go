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

func TestDropsStaleByTTL(t *testing.T) {
	r := NewReceiver(50 * time.Millisecond)
	f := Frame{
		Seq:         1,
		TimestampMS: time.Now().Add(-200 * time.Millisecond).UnixMilli(),
		Payload:     []byte("late"),
	}

	ok, reason := r.Accept(f)
	if ok {
		t.Fatalf("expected stale frame to be dropped")
	}
	if reason != "ttl exceeded" {
		t.Fatalf("expected reason 'ttl exceeded', got %q", reason)
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
