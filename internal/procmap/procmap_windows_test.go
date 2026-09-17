//go:build windows

package procmap

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRefreshResolvesOwnProcess opens a real UDP socket bound to an
// ephemeral port in this test process, refreshes the table against the
// live OS socket state, and asserts that port resolves back to this
// test binary's own executable name — a real check against the actual
// Windows IP Helper API, not a mock.
func TestRefreshResolvesOwnProcess(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("open test UDP socket: %v", err)
	}
	defer conn.Close()

	_, portStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("parse local addr: %v", err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	port := uint16(portNum)

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	wantName := strings.ToLower(filepath.Base(exe))

	table := New()

	// The OS socket table can lag a moment behind a just-opened socket
	// on some systems — retry briefly rather than flake.
	var gotName string
	var ok bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := table.Refresh(); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		gotName, ok = table.ProcessForUDPPort(port)
		if ok {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !ok {
		t.Fatalf("port %d not found in UDP table after refresh", port)
	}
	if gotName != wantName {
		t.Errorf("port %d resolved to %q, want %q", port, gotName, wantName)
	}
}

// TestProcessForUnknownPortNotFound is the trivial negative case — a
// port nothing has ever bound shouldn't resolve to anything.
func TestProcessForUnknownPortNotFound(t *testing.T) {
	table := New()
	if err := table.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// Port 1 is reserved/almost never bound; if this ever flakes because
	// something legitimately owns it, that's more interesting than the
	// test itself.
	if _, ok := table.ProcessForUDPPort(1); ok {
		t.Skip("port 1 unexpectedly owned by something on this machine — not a useful negative case here")
	}
}
