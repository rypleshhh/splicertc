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

// Open a UDP socket and check that its port maps to our own exe.
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

	// the table can lag a bit, retry
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

func TestProcessForUnknownPortNotFound(t *testing.T) {
	table := New()
	if err := table.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// nothing should be on port 1
	if _, ok := table.ProcessForUDPPort(1); ok {
		t.Skip("something is using port 1")
	}
}
