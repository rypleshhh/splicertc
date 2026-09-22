package main

import (
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	logger = log.New(io.Discard, "", 0)
	m.Run()
}

func TestScanForConnectedDetectsMarker(t *testing.T) {
	r := strings.NewReader("loaded config from client-config.json\nconnected to vpn channel 1.2.3.4:587\nsome later noise\n")
	ch := make(chan bool, 1)
	scanForConnected(r, ch)

	select {
	case ok := <-ch:
		if !ok {
			t.Fatal("expected true (marker seen) before the stream ended")
		}
	default:
		t.Fatal("expected a result on connectedCh, got none")
	}
}

func TestScanForConnectedReportsFalseWhenStreamEndsFirst(t *testing.T) {
	r := strings.NewReader("loaded config from client-config.json\ndial server: connection refused\n")
	ch := make(chan bool, 1)
	scanForConnected(r, ch)

	select {
	case ok := <-ch:
		if ok {
			t.Fatal("expected false — the stream ended without the connected marker ever appearing")
		}
	default:
		t.Fatal("expected a result on connectedCh, got none")
	}
}

func TestScanForConnectedIgnoresPartialMatchAcrossLines(t *testing.T) {
	// The marker text split across two separate log lines must not
	// falsely trigger — scanForConnected checks per completed line.
	r := strings.NewReader("connected to vpn\nchannel 1.2.3.4:587\n")
	ch := make(chan bool, 1)
	scanForConnected(r, ch)

	select {
	case ok := <-ch:
		if ok {
			t.Fatal("expected false — the marker text was split across two lines, neither of which contains it whole")
		}
	default:
		t.Fatal("expected a result on connectedCh, got none")
	}
}

func TestContainsConnected(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"2026/09/22 12:00:00 connected to vpn channel 1.2.3.4:587", true},
		{"connected to vpn channel", true},
		{"connected to glue channel 1.2.3.4:993 over 3 path(s) for: deadlock.exe", false},
		{"", false},
		{"dial server: connection refused", false},
	}
	for _, c := range cases {
		if got := containsConnected([]byte(c.line)); got != c.want {
			t.Errorf("containsConnected(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestScanForConnectedDoesNotBlockOnUnbufferedChannel is a light
// concurrency sanity check: connectedCh is typically buffered size 1 in
// real use (two goroutines, stdout and stderr, both racing to report),
// but scanForConnected must not deadlock even if the receiver is slow.
func TestScanForConnectedDoesNotBlockOnUnbufferedChannel(t *testing.T) {
	r := strings.NewReader("connected to vpn channel 1.2.3.4:587\n")
	ch := make(chan bool, 1)

	done := make(chan struct{})
	go func() {
		scanForConnected(r, ch)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scanForConnected did not return in time — possible deadlock on a full/unread channel")
	}
}
