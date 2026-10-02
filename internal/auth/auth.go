// Package auth checks that a client is allowed to use the server.
// Each client has its own Ed25519 key, the server keeps a list of
// allowed public keys (authorized_keys.json).
//
// Handshake: server sends a random challenge, client signs
// prefix + challenge + TLS exporter value and sends back its public key
// and the signature. The exporter value is different for every TLS
// session, so a signature can't be reused on another connection.
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

// prefix so these signatures can't be mixed up with anything else
const authContext = "splicertc-auth-v1"

const exporterLabel = "splicertc-auth-binding"
const exporterLen = 32

// GenerateKeypair returns a public key (for authorized_keys.json) and a
// private seed (for the client config).
func GenerateKeypair() (pub, seed []byte, err error) {
	p, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return p, priv.Seed(), nil
}

// Keys are stored as base64 in config files.
func EncodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func DecodeKey(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// LoadClientKey reads a base64 seed from a file (client_key_file).
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

// AuthorizedEntry is one entry in authorized_keys.json.
type AuthorizedEntry struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type AuthorizedKeys struct {
	byKey map[string]string // pubkey bytes -> name
}

// LoadAuthorizedKeys reads authorized_keys.json.
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

// ensureTLS makes sure the handshake is done (server side conns do it
// lazily) because we need the TLS exporter.
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

// bindingMessage is the data that gets signed.
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

// ServerHandshake checks the client and returns its name from
// authorized_keys.json.
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

// ClientHandshake signs the server's challenge with our key.
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
