package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCert builds a throwaway self-signed cert/key pair, the same
// shape cmd/gencert produces, entirely in memory (no disk, no
// dependency on the gencert binary).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func fingerprintOf(cert tls.Certificate) []byte {
	sum := sha256.Sum256(cert.Certificate[0])
	return sum[:]
}

// listenWith starts a bare TLS listener presenting cert, and returns
// its address. Not transport.Listen (which reads cert/key from disk) —
// this test builds certs in memory instead.
func listenWith(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// crypto/tls's handshake is lazy (happens on first
				// Read/Write) — force it to complete server-side before
				// this connection can be closed out from under a client
				// that's still mid-handshake itself.
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestDialAcceptsPinnedCert proves the ordinary, expected path: dialing
// with the real server's own fingerprint as the pin succeeds.
func TestDialAcceptsPinnedCert(t *testing.T) {
	certA := selfSignedCert(t)
	addr := listenWith(t, certA)

	conn, err := Dial(addr, false, fingerprintOf(certA))
	if err != nil {
		t.Fatalf("expected Dial to succeed against the pinned cert, got: %v", err)
	}
	conn.Close()
}

// TestDialRejectsWrongCert is the direct regression test for IDEAS.md's
// P0 #3: it simulates a MITM by pointing the client's pin (for the real
// server's cert A) at a *different* listener presenting cert B — the
// same shape a TLS-intercepting middlebox would have, since it can't
// produce a certificate matching cert A's fingerprint without cert A's
// private key. Without pinning (plain insecure:true, tested for
// contrast below) this would silently succeed; with pinning it must
// fail the handshake outright, proving a party without the pinned
// cert's private key cannot complete a connection under that pin.
func TestDialRejectsWrongCert(t *testing.T) {
	certA := selfSignedCert(t)
	certB := selfSignedCert(t) // stands in for a MITM's own certificate
	addrB := listenWith(t, certB)

	_, err := Dial(addrB, false, fingerprintOf(certA))
	if err == nil {
		t.Fatal("expected Dial to reject a connection presenting a certificate that doesn't match the pin, but it succeeded")
	}
}

// TestDialInsecureWithoutPinAcceptsAnything documents the pre-pinning
// behavior this fix is meant to close: with pin == nil, insecure:true
// still accepts any certificate at all — the exact gap a MITM exploits.
// This isn't asserting new behavior, just pinning down (no pun
// intended) that the old insecure-only path is unchanged and still
// opt-in, so pin is additive rather than a silent behavior change for
// existing configs that don't set it.
func TestDialInsecureWithoutPinAcceptsAnything(t *testing.T) {
	certB := selfSignedCert(t)
	addrB := listenWith(t, certB)

	conn, err := Dial(addrB, true, nil)
	if err != nil {
		t.Fatalf("expected insecure Dial with no pin to accept any cert, got: %v", err)
	}
	conn.Close()
}
