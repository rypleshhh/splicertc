// Package auth gates every tunnel connection behind a pre-shared key,
// checked right after the TLS handshake and before any protocol logic
// (SOCKS5, droppable frames, or glue/UDP relay) runs. Without this,
// anyone who finds the server's IP:port can use it as an open SOCKS5
// proxy or an open UDP relay — the latter is a textbook building block
// for amplification DDoS (attacker asks the server to blast traffic at
// a victim's IP, ostensibly "relaying a game").
//
// This is a symmetric shared secret (HMAC challenge-response), not
// public-key auth — deliberately. Public-key auth earns its complexity
// when you need to tell multiple distinct identities apart or hand out
// credentials you can revoke individually. Here there's exactly one
// trusted client and one server the person controls personally; a
// shared secret both sides already have out-of-band (you typed it into
// both configs) does the same job — proving "you know the secret" —
// with far less code and no key-management story to get wrong.
//
// Protocol: server sends a random 32-byte challenge; client responds
// with HMAC-SHA256(key, challenge). The key itself never crosses the
// wire, so even if this weren't already inside TLS, a passive observer
// gains nothing replayable — each challenge is fresh.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const challengeSize = 32
const macSize = sha256.Size

// LoadKey reads a shared-secret file and derives a fixed-size key from
// it via SHA-256 — so the passphrase in the file can be any length or
// format, whitespace-trimmed. Keep this file's permissions tight
// (chmod 600); don't pass the secret as a command-line flag, since
// flags are visible to any local user via /proc/<pid>/cmdline.
func LoadKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("key file %s is empty", path)
	}
	sum := sha256.Sum256([]byte(trimmed))
	return sum[:], nil
}

// ServerHandshake challenges the connection and verifies the response.
// Returns an error (and the caller should close the connection) if the
// client doesn't know the key.
func ServerHandshake(conn net.Conn, key []byte) error {
	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate challenge: %w", err)
	}
	if _, err := conn.Write(challenge); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}

	resp := make([]byte, macSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	want := hmac.New(sha256.New, key)
	want.Write(challenge)
	expected := want.Sum(nil)

	if !hmac.Equal(resp, expected) {
		return fmt.Errorf("authentication failed: wrong key")
	}
	return nil
}

// ClientHandshake answers a server's challenge.
func ClientHandshake(conn net.Conn, key []byte) error {
	challenge := make([]byte, challengeSize)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(challenge)
	resp := mac.Sum(nil)

	if _, err := conn.Write(resp); err != nil {
		return fmt.Errorf("send response: %w", err)
	}
	return nil
}
