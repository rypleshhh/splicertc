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
		if _, banned, _ := checkAuthBan(ip); banned {
			t.Fatalf("expected no ban after %d failure(s) (threshold is %d)", i+1, maxAuthFailures)
		}
	}

	recordAuthFailure(ip)
	until, banned, _ := checkAuthBan(ip)
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
	if _, banned, _ := checkAuthBan(ip); banned {
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

	if _, banned, _ := checkAuthBan(ip); banned {
		t.Error("expected an expired ban to no longer report as banned")
	}

	authFailures.mu.Lock()
	_, stillPresent := authFailures.bannedUntil[ip]
	authFailures.mu.Unlock()
	if stillPresent {
		t.Error("expected checkAuthBan to clear an expired ban's map entry, not just ignore it")
	}
}

// A banned IP is logged once per ban, not on every retry.
func TestBanRejectionLoggedOnce(t *testing.T) {
	ip := "198.51.100.77"
	defer recordAuthSuccess(ip)
	for i := 0; i < maxAuthFailures; i++ {
		recordAuthFailure(ip)
	}
	_, banned, first := checkAuthBan(ip)
	if !banned || !first {
		t.Fatalf("first rejection: banned=%v first=%v", banned, first)
	}
	if _, _, first := checkAuthBan(ip); first {
		t.Fatal("second rejection of the same ban was marked as first")
	}
}

// When a ban runs out, the count starts from zero again: one more
// failure must not ban right away.
func TestExpiredBanResetsCount(t *testing.T) {
	tests := []struct {
		name   string
		expire func(ip string)
	}{
		{"janitor", func(string) { cleanupAuthFailures(time.Now()) }},
		{"next connection", func(ip string) { checkAuthBan(ip) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := "test-expired-ban-" + tt.name
			for i := 0; i < maxAuthFailures; i++ {
				recordAuthFailure(ip)
			}
			authFailures.mu.Lock()
			authFailures.bannedUntil[ip] = time.Now().Add(-time.Second)
			authFailures.mu.Unlock()

			tt.expire(ip)
			recordAuthFailure(ip)
			if _, banned, _ := checkAuthBan(ip); banned {
				t.Fatal("banned again after a single failure once the old ban expired")
			}
		})
	}
}

// An IP with a recent successful login is shared (dorm NAT) and is not
// banned; once the success is old enough, failures ban as usual.
func TestNoBanAfterRecentSuccess(t *testing.T) {
	ip := "test-no-ban-after-success"
	recordAuthSuccess(ip)
	for i := 0; i < maxAuthFailures+2; i++ {
		recordAuthFailure(ip)
	}
	if _, banned, _ := checkAuthBan(ip); banned {
		t.Fatal("an IP with a successful login in the last 24h was banned")
	}

	authFailures.mu.Lock()
	authFailures.lastSuccess[ip] = time.Now().Add(-authTrustAfterSuccess - time.Minute)
	authFailures.mu.Unlock()
	recordAuthFailure(ip)
	if _, banned, _ := checkAuthBan(ip); !banned {
		t.Fatal("expected a ban once the last success is older than 24h")
	}
	recordAuthSuccess(ip)
}

func TestOldSuccessIsForgotten(t *testing.T) {
	ip := "test-old-success-forgotten"
	recordAuthSuccess(ip)
	cleanupAuthFailures(time.Now().Add(authTrustAfterSuccess + time.Minute))
	authFailures.mu.Lock()
	_, left := authFailures.lastSuccess[ip]
	authFailures.mu.Unlock()
	if left {
		t.Fatal("a success older than 24h was not forgotten")
	}
}

func TestBanKey(t *testing.T) {
	tests := []struct {
		ip, want string
	}{
		{"203.0.113.5", "203.0.113.5"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"::ffff:203.0.113.5", "::ffff:203.0.113.5"}, // IPv4-mapped stays per address
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := banKey(tt.ip); got != tt.want {
				t.Fatalf("banKey(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// Failures from different addresses of one IPv6 /64 add up to one ban.
func TestIPv6BanByPrefix(t *testing.T) {
	addrs := []string{"2001:db8:77::1", "2001:db8:77::2", "2001:db8:77::3"}
	key := banKey(addrs[0])
	defer recordAuthSuccess(key)
	for _, a := range addrs[:maxAuthFailures] {
		recordAuthFailure(banKey(a))
	}
	if _, banned, _ := checkAuthBan(banKey("2001:db8:77::ffff")); !banned {
		t.Fatal("another address of the same /64 is not banned")
	}
	if _, banned, _ := checkAuthBan(banKey("2001:db8:78::1")); banned {
		t.Fatal("a different /64 got banned too")
	}
}
