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

func TestScanForConnected(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{"marker", "loaded config from client-config.json\nconnected to vpn channel 1.2.3.4:587\nsome later noise\n",
			"connected to vpn channel 1.2.3.4:587"},
		{"CRLF output", "starting\r\nconnected to vpn channel 1.2.3.4:587\r\n", "connected to vpn channel 1.2.3.4:587"},
		{"stream ends first", "loaded config from client-config.json\ndial server: connection refused\n", ""},
		// marker split over two lines must not match
		{"split marker", "connected to vpn\nchannel 1.2.3.4:587\n", ""},
		// lines after the first connect go to onClientLine; with the
		// tunnel not up yet (no GUI here) it must not touch anything
		{"reconnect lines", "connected to vpn channel 1.2.3.4:587\nvpn: connection lost (EOF), reconnecting\nconnected to vpn channel 1.2.3.4:587\n",
			"connected to vpn channel 1.2.3.4:587"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch := make(chan string, 1)
			scanForConnected(strings.NewReader(c.output), ch)
			select {
			case got := <-ch:
				if got != c.want {
					t.Fatalf("got %q, want %q", got, c.want)
				}
			default:
				t.Fatal("expected a result on connectedCh, got none")
			}
		})
	}
}

// scanForConnected must not block when nobody reads the channel (two
// scanners share it, only one result is taken).
func TestScanForConnectedDoesNotBlockOnFullChannel(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "already full"

	done := make(chan struct{})
	go func() {
		scanForConnected(strings.NewReader("connected to vpn channel 1.2.3.4:587\n"), ch)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scanForConnected blocked")
	}
}

// The fatal errors of client.exe are recognised, so the tray can explain them.
func TestNoteClientLine(t *testing.T) {
	cases := []struct {
		line string
		want clientErrKind
	}{
		{"2026/10/14 vpn: reconnect: server certificate does not match pinned fingerprint", errPinMismatch},
		{"dial vpn channel: server rejected the client key (is its public key in the server's authorized_keys.json?)", errKeyRejected},
		{"vpn: connection lost (EOF), reconnecting", errNone},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			lastClientErr.Store(int32(errNone))
			noteClientLine(c.line)
			if got := clientErrKind(lastClientErr.Load()); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
	lastClientErr.Store(int32(errNone))
}
