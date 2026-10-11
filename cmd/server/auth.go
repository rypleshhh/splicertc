package main

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"tcp-dormtun/internal/auth"
)

// nil means auth is off
var authorizedKeys *auth.AuthorizedKeys

// Ban an IP for authBanDuration after maxAuthFailures failed logins.
// Failures older than authFailureMemory are forgotten.
const (
	maxAuthFailures   = 3
	authBanDuration   = 10 * time.Minute
	authFailureMemory = 30 * time.Minute
)

// A client that connects and never finishes TLS + auth + session ID is
// dropped after this, otherwise anyone could hold thousands of sockets open.
const handshakeTimeout = 15 * time.Second

var authFailures = struct {
	mu          sync.Mutex
	count       map[string]int
	lastFailure map[string]time.Time
	bannedUntil map[string]time.Time
}{
	count:       make(map[string]int),
	lastFailure: make(map[string]time.Time),
	bannedUntil: make(map[string]time.Time),
}

// authIP returns the remote IP without the port.
func authIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// checkAuthBan also removes expired bans.
func checkAuthBan(ip string) (until time.Time, banned bool) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	until, banned = authFailures.bannedUntil[ip]
	if !banned {
		return time.Time{}, false
	}
	if time.Now().After(until) {
		delete(authFailures.bannedUntil, ip)
		delete(authFailures.count, ip)
		delete(authFailures.lastFailure, ip)
		return time.Time{}, false
	}
	return until, true
}

func recordAuthFailure(ip string) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	authFailures.count[ip]++
	authFailures.lastFailure[ip] = time.Now()
	if authFailures.count[ip] >= maxAuthFailures {
		until := time.Now().Add(authBanDuration)
		authFailures.bannedUntil[ip] = until
		log.Printf("auth: banning %s until %s after %d failed attempts", ip, until.Format(time.RFC3339), authFailures.count[ip])
	}
}

func recordAuthSuccess(ip string) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	delete(authFailures.count, ip)
	delete(authFailures.lastFailure, ip)
	delete(authFailures.bannedUntil, ip)
}

// cleanupAuthFailures forgets old failures and expired bans, so the maps
// don't grow forever when scanners come from many different IPs.
func cleanupAuthFailures(now time.Time) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	for ip, until := range authFailures.bannedUntil {
		if now.After(until) {
			delete(authFailures.bannedUntil, ip)
		}
	}
	for ip, last := range authFailures.lastFailure {
		if _, banned := authFailures.bannedUntil[ip]; !banned && now.Sub(last) > authFailureMemory {
			delete(authFailures.lastFailure, ip)
			delete(authFailures.count, ip)
		}
	}
}

// checkAuth runs the auth handshake (if enabled) and returns the client
// name. Must be called right after Accept, after startHandshake.
func checkAuth(conn net.Conn) (name string, ok bool) {
	if authorizedKeys == nil {
		return "", true
	}

	ip := authIP(conn)
	if until, banned := checkAuthBan(ip); banned {
		log.Printf("auth: rejected %s: banned until %s (too many failed attempts)", conn.RemoteAddr(), until.Format(time.RFC3339))
		return "", false
	}

	name, err := auth.ServerHandshake(conn, authorizedKeys)
	if err != nil {
		log.Printf("auth: rejected %s: %v", conn.RemoteAddr(), err)
		// only a wrong key counts towards the ban, not network errors:
		// clients reconnect by themselves and a bad link shouldn't ban them
		if errors.Is(err, auth.ErrUnauthorized) {
			recordAuthFailure(ip)
		}
		return "", false
	}
	recordAuthSuccess(ip)
	return name, true
}

// startHandshake puts a deadline on the whole connection setup (TLS,
// auth, session ID). Call endHandshake when the setup is done.
func startHandshake(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
}

func endHandshake(conn net.Conn) {
	_ = conn.SetDeadline(time.Time{})
}
