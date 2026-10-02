package main

import (
	"net"
	"testing"
	"time"
)

// Failures are counted per IP, so the port must be removed.
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

// maxAuthFailures failures -> ban, one less -> no ban.
func TestBanAfterMaxFailures(t *testing.T) {
	ip := "test-ban-after-max-failures"

	for i := 0; i < maxAuthFailures-1; i++ {
		recordAuthFailure(ip)
		if _, banned := checkAuthBan(ip); banned {
			t.Fatalf("expected no ban after %d failure(s) (threshold is %d)", i+1, maxAuthFailures)
		}
	}

	recordAuthFailure(ip)
	until, banned := checkAuthBan(ip)
	if !banned {
		t.Fatalf("expected a ban after %d failures", maxAuthFailures)
	}
	if !until.After(time.Now()) {
		t.Errorf("expected the ban to expire in the future, got %v", until)
	}
}

// A successful login resets the counter.
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

// Expired ban should be removed.
func TestBanExpires(t *testing.T) {
	ip := "test-ban-expires"

	authFailures.mu.Lock()
	authFailures.count[ip] = maxAuthFailures
	authFailures.bannedUntil[ip] = time.Now().Add(-time.Minute)
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
