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
	// a whole dorm is often behind one NAT IP: an IP with a successful
	// login this recently is not banned, one wrong key there must not
	// lock out everybody else
	authTrustAfterSuccess = 24 * time.Hour
)

// A client that connects and never finishes TLS + auth + session ID is
// dropped after this, otherwise anyone could hold thousands of sockets open.
const handshakeTimeout = 15 * time.Second

var authFailures = struct {
	mu          sync.Mutex
	count       map[string]int
	lastFailure map[string]time.Time
	bannedUntil map[string]time.Time
	// banned IPs whose rejection was already logged: a scanner retrying
	// every second would otherwise write a log line every second
	banLogged   map[string]bool
	lastSuccess map[string]time.Time
}{
	count:       make(map[string]int),
	lastFailure: make(map[string]time.Time),
	bannedUntil: make(map[string]time.Time),
	banLogged:   make(map[string]bool),
	lastSuccess: make(map[string]time.Time),
}

// authIP returns the remote IP without the port.
func authIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// banKey is what failures are counted for: the IP, or for IPv6 its /64.
// An IPv6 client usually gets a whole /64 and can pick any address in it.
func banKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	prefix := net.IPNet{IP: parsed.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}
	return prefix.String()
}

// clearBanLocked forgets everything about failures of ip, so after a ban
// the count starts from zero. Called with authFailures.mu held.
func clearBanLocked(ip string) {
	delete(authFailures.bannedUntil, ip)
	delete(authFailures.count, ip)
	delete(authFailures.lastFailure, ip)
	delete(authFailures.banLogged, ip)
}

// checkAuthBan also removes expired bans. firstReject is true only for
// the first rejected connection of a ban, so it's logged once.
func checkAuthBan(ip string) (until time.Time, banned, firstReject bool) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	until, banned = authFailures.bannedUntil[ip]
	if !banned {
		return time.Time{}, false, false
	}
	if time.Now().After(until) {
		clearBanLocked(ip)
		return time.Time{}, false, false
	}
	firstReject = !authFailures.banLogged[ip]
	authFailures.banLogged[ip] = true
	return until, true, firstReject
}

func recordAuthFailure(ip string) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	now := time.Now()
	authFailures.count[ip]++
	authFailures.lastFailure[ip] = now
	count := authFailures.count[ip]
	if count < maxAuthFailures {
		return
	}
	if last, ok := authFailures.lastSuccess[ip]; ok && now.Sub(last) < authTrustAfterSuccess {
		if count == maxAuthFailures {
			log.Printf("auth: not banning %s after %d failed attempts: it had a successful login at %s (shared NAT?)",
				ip, count, last.Format(time.RFC3339))
		}
		return
	}
	until := now.Add(authBanDuration)
	authFailures.bannedUntil[ip] = until
	log.Printf("auth: banning %s until %s after %d failed attempts", ip, until.Format(time.RFC3339), count)
}

func recordAuthSuccess(ip string) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	clearBanLocked(ip)
	authFailures.lastSuccess[ip] = time.Now()
}

// cleanupAuthFailures forgets old failures and expired bans, so the maps
// don't grow forever when scanners come from many different IPs.
func cleanupAuthFailures(now time.Time) {
	authFailures.mu.Lock()
	defer authFailures.mu.Unlock()
	for ip, until := range authFailures.bannedUntil {
		if now.After(until) {
			// the count too, or the next single failure bans again
			clearBanLocked(ip)
		}
	}
	for ip, last := range authFailures.lastFailure {
		if _, banned := authFailures.bannedUntil[ip]; !banned && now.Sub(last) > authFailureMemory {
			delete(authFailures.lastFailure, ip)
			delete(authFailures.count, ip)
		}
	}
	for ip, last := range authFailures.lastSuccess {
		if now.Sub(last) > authTrustAfterSuccess {
			delete(authFailures.lastSuccess, ip)
		}
	}
}

// checkAuth runs the auth handshake (if enabled) and returns the client
// name. Must be called right after Accept, after startHandshake.
func checkAuth(conn net.Conn) (name string, ok bool) {
	if authorizedKeys == nil {
		return "", true
	}

	ip := banKey(authIP(conn))
	if until, banned, first := checkAuthBan(ip); banned {
		if first {
			log.Printf("auth: rejecting %s until %s (banned after too many failed attempts; further attempts are not logged)", ip, until.Format(time.RFC3339))
		}
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
