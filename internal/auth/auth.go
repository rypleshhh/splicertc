// Package auth gates every tunnel connection behind Ed25519 client
// identity, checked right after the TLS handshake and before any
// protocol logic (SOCKS5, droppable frames, or glue/UDP relay) runs.
// Without this, anyone who finds the server's IP:port can use it as an
// open SOCKS5 proxy or an open UDP relay — the latter is a textbook
// building block for amplification DDoS (attacker asks the server to
// blast traffic at a victim's IP, ostensibly "relaying a game").
//
// This is per-client Ed25519 signing, not a single shared secret: the
// server holds a list of authorized public keys (authorized_keys.json,
// one entry per person allowed to connect), each client holds its own
// private key. That earns its complexity here because there's now
// genuinely more than one trusted identity — sharing tunnel access with
// friends means being able to tell them apart and revoke one without
// rotating a secret everyone else also has to update. A compromised
// server (disk/backup read) only exposes public keys, which are useless
// for impersonation; a compromised distribution channel (sending a
// friend their key over chat) only needs to protect the friend's own
// private key file, not something that flows through the same channel
// used to add them in the first place — their public key can be shared
// in the open.
//
// Protocol: server sends a random 32-byte challenge; client signs
// domain-separated-prefix || challenge || this-TLS-session's-exporter-
// value with its private key and sends back its public key + signature.
// The TLS exporter binding (see bindingMessage) means a captured
// signature is worthless replayed on any other connection, even to the
// same server — closing the generic "relay a challenge through a second
// connection" class of attack regardless of the random challenge alone.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const challengeSize = 32

// authContext domain-separates this protocol's signatures from any
// other hypothetical use of the same Ed25519 key — defense in depth,
// cheap to include: even if a client's key were ever reused for
// something else, a signature produced there could never be replayed
// here, and vice versa.
const authContext = "splicertc-auth-v1"

// exporterLabel/exporterLen: the TLS-exporter contribution to the
// signed message (see bindingMessage).
const exporterLabel = "splicertc-auth-binding"
const exporterLen = 32

// GenerateKeypair creates a new Ed25519 identity: pub is the 32-byte
// public key (an entry in the server's authorized_keys.json), seed is
// the 32-byte private seed (a client's client_key/client_key_file —
// never share it, treat it exactly like the old psk).
func GenerateKeypair() (pub, seed []byte, err error) {
	p, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return p, priv.Seed(), nil
}

// EncodeKey/DecodeKey are the base64 form used for both public keys and
// private seeds in config files and authorized_keys.json.
func EncodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func DecodeKey(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// LoadClientKey reads a base64-encoded Ed25519 seed from a file — the
// client_key_file config field, analogous to the old psk_file.
func LoadClientKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client key file: %w", err)
	}
	seed, err := DecodeKey(string(raw))
	if err != nil {
		return nil, fmt.Errorf("client key file %s: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("client key file %s: expected a %d-byte seed, got %d bytes", path, ed25519.SeedSize, len(seed))
	}
	return seed, nil
}

// AuthorizedEntry is one line of authorized_keys.json.
type AuthorizedEntry struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// AuthorizedKeys is the server's set of clients allowed to connect,
// keyed by raw public key bytes so ServerHandshake can look one up in
// O(1) and report back which name it belongs to (for logging).
type AuthorizedKeys struct {
	byKey map[string]string // raw pubkey bytes (as a string) -> name
}

// LoadAuthorizedKeys reads authorized_keys.json: a JSON array of
// {"name", "public_key"} entries, one per person allowed to connect.
// Revoking someone is deleting their entry and restarting the server.
func LoadAuthorizedKeys(path string) (*AuthorizedKeys, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorized keys file: %w", err)
	}
	var entries []AuthorizedEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse authorized keys file %s: %w", path, err)
	}
	ak := &AuthorizedKeys{byKey: make(map[string]string, len(entries))}
	for _, e := range entries {
		pub, err := DecodeKey(e.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("authorized keys file %s: entry %q: %w", path, e.Name, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authorized keys file %s: entry %q: expected a %d-byte public key, got %d bytes", path, e.Name, ed25519.PublicKeySize, len(pub))
		}
		ak.byKey[string(pub)] = e.Name
	}
	return ak, nil
}

// ensureTLS confirms conn is a TLS connection with its handshake
// complete (Handshake is a no-op if it already ran — this just also
// covers the server side's lazily-handshaking Accept()ed connections).
// Auth strictly requires TLS: bindingMessage's exporter step is what
// closes the cross-connection relay class described in the package doc,
// and that has no meaning without a TLS session to bind to.
func ensureTLS(conn net.Conn) (*tls.Conn, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("auth requires a TLS connection")
	}
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tc, nil
}

// bindingMessage is exactly what gets signed: a domain-separation
// prefix, the server's random challenge, and a TLS exporter value
// unique to this specific session. Without the exporter, a party that
// can merely relay bytes between two separate connections to the real
// server — without ever holding a private key — could get a legitimate
// client to sign a forwarded challenge and reuse that signature itself
// on its own connection; the exporter value differs per TLS session
// (even with an identical challenge), so a signature computed for one
// connection fails verification on any other.
func bindingMessage(tc *tls.Conn, challenge []byte) ([]byte, error) {
	cs := tc.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(exporterLabel, nil, exporterLen)
	if err != nil {
		return nil, fmt.Errorf("export TLS keying material: %w", err)
	}
	msg := make([]byte, 0, len(authContext)+len(challenge)+len(exporter))
	msg = append(msg, authContext...)
	msg = append(msg, challenge...)
	msg = append(msg, exporter...)
	return msg, nil
}

// ServerHandshake challenges the connection, verifies the signed
// response against the authorized-keys set, and returns the matching
// name. Returns an error (the caller should close the connection) if
// the client doesn't hold an authorized private key.
func ServerHandshake(conn net.Conn, keys *AuthorizedKeys) (string, error) {
	tc, err := ensureTLS(conn)
	if err != nil {
		return "", err
	}

	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	if _, err := conn.Write(challenge); err != nil {
		return "", fmt.Errorf("send challenge: %w", err)
	}

	resp := make([]byte, ed25519.PublicKeySize+ed25519.SignatureSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	pub := ed25519.PublicKey(resp[:ed25519.PublicKeySize])
	sig := resp[ed25519.PublicKeySize:]

	name, known := keys.byKey[string(pub)]
	if !known {
		return "", fmt.Errorf("authentication failed: unrecognized public key")
	}

	msg, err := bindingMessage(tc, challenge)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return "", fmt.Errorf("authentication failed: invalid signature for %q", name)
	}
	return name, nil
}

// ClientHandshake answers a server's challenge by signing it (bound to
// this TLS session — see bindingMessage) with the private key derived
// from seed, and sends the corresponding public key alongside so the
// server can look up which authorized identity it belongs to.
func ClientHandshake(conn net.Conn, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("client key: expected a %d-byte seed, got %d bytes", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)

	tc, err := ensureTLS(conn)
	if err != nil {
		return err
	}

	challenge := make([]byte, challengeSize)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}

	msg, err := bindingMessage(tc, challenge)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, msg)

	resp := make([]byte, 0, ed25519.PublicKeySize+len(sig))
	resp = append(resp, priv.Public().(ed25519.PublicKey)...)
	resp = append(resp, sig...)
	if _, err := conn.Write(resp); err != nil {
		return fmt.Errorf("send response: %w", err)
	}
	return nil
}
