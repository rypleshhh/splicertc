package main

import (
	"strings"
	"testing"
	"time"

	"tcp-dormtun/internal/frame"
)

// Past the seen cap new frame numbers are not counted, so delivered can't
// get bigger than seen (negative loss).
func TestDropSessionCountsUpToCap(t *testing.T) {
	s := &dropSession{recv: frame.NewReceiver(time.Hour), seen: make(map[uint32]struct{})}
	for seq := uint32(0); seq < maxDropSeen+50; seq++ {
		s.record(frame.New(seq, nil))
	}
	// a copy of a counted frame is still counted as a duplicate
	s.record(frame.New(maxDropSeen-1, nil))

	if s.accepted != maxDropSeen || len(s.seen) != maxDropSeen {
		t.Fatalf("accepted %d, seen %d, want both %d", s.accepted, len(s.seen), maxDropSeen)
	}
	if s.duplicates != 1 {
		t.Fatalf("duplicates %d, want 1", s.duplicates)
	}
	sum := s.summary()
	if !strings.Contains(sum, "0 never delivered") || !strings.Contains(sum, "only the first") {
		t.Fatalf("unexpected summary: %s", sum)
	}
}
