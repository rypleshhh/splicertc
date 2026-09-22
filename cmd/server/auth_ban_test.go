package main

import (
	"net"
	"testing"
	"time"
)

// TestAuthIPStripsPort confirms failures are tracked per source IP, not
// per source port — two connections from the same machine on different
// ephemeral ports must count against the same ban bucket.
func TestAuthIPStripsPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serverCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-serverCh
	defer server.Close()

	if ip := authIP(server); ip != "127.0.0.1" {
		t.Errorf("expected authIP to strip the port and return \"127.0.0.1\", got %q", ip)
	}
}

// TestBanAfterMaxFailures is the direct regression test for the
// brute-force defense: exactly maxAuthFailures failures ban the IP, one
// fewer doesn't.
func TestBanAfterMaxFailures(t *testing.T) {
	ip := "test-ban-after-max-failures"

	for i := 0; i < maxAuthFailures-1; i++ {
		recordAuthFailure(ip)
		if _, banned := checkAuthBan(ip); banned {
			t.Fatalf("expected no ban after %d failure(s) (threshold is %d)", i+1, maxAuthFailures)
		}
	}

	recordAuthFailure(ip) // the maxAuthFailures-th failure
	until, banned := checkAuthBan(ip)
	if !banned {
		t.Fatalf("expected a ban after %d failures", maxAuthFailures)
	}
	if !until.After(time.Now()) {
		t.Errorf("expected the ban to expire in the future, got %v", until)
	}
}

// TestBanClearsOnSuccess proves a successful auth resets the counter —
// a legitimate client that mistyped its key a couple of times before
// getting it right shouldn't stay one failure away from a ban forever.
func TestBanClearsOnSuccess(t *testing.T) {
	ip := "test-ban-clears-on-success"

	for i := 0; i < maxAuthFailures-1; i++ {
		recordAuthFailure(ip)
	}
	recordAuthSuccess(ip)

	recordAuthFailure(ip)
	if _, banned := checkAuthBan(ip); banned {
		t.Error("expected a successful auth to reset the failure count, but the IP is already banned after one more failure")
	}
}

// TestBanExpires proves an expired ban is treated as not-banned and its
// bookkeeping is actually cleared, not just skipped for this one check.
func TestBanExpires(t *testing.T) {
	ip := "test-ban-expires"

	authFailures.mu.Lock()
	authFailures.count[ip] = maxAuthFailures
	authFailures.bannedUntil[ip] = time.Now().Add(-time.Minute) // already expired
	authFailures.mu.Unlock()

	if _, banned := checkAuthBan(ip); banned {
		t.Error("expected an expired ban to no longer report as banned")
	}

	authFailures.mu.Lock()
	_, stillPresent := authFailures.bannedUntil[ip]
	authFailures.mu.Unlock()
	if stillPresent {
		t.Error("expected checkAuthBan to clear an expired ban's map entry, not just ignore it")
	}
}
