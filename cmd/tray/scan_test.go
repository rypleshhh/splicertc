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
			t.Fatal("expected false, there was no marker")
		}
	default:
		t.Fatal("expected a result on connectedCh, got none")
	}
}

func TestScanForConnectedIgnoresPartialMatchAcrossLines(t *testing.T) {
	// marker split over two lines should not match
	r := strings.NewReader("connected to vpn\nchannel 1.2.3.4:587\n")
	ch := make(chan bool, 1)
	scanForConnected(r, ch)

	select {
	case ok := <-ch:
		if ok {
			t.Fatal("expected false, marker is split over two lines")
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

// scanForConnected must not block if nobody reads the channel.
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
		t.Fatal("scanForConnected blocked")
	}
}
