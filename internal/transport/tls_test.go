package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCert makes an in-memory self-signed cert for tests.
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

// listenWith starts a TLS listener with cert and returns its address.
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
				// finish the handshake before closing, it's lazy in crypto/tls
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestDialAcceptsPinnedCert(t *testing.T) {
	certA := selfSignedCert(t)
	addr := listenWith(t, certA)

	conn, err := Dial(addr, false, fingerprintOf(certA))
	if err != nil {
		t.Fatalf("expected Dial to succeed against the pinned cert, got: %v", err)
	}
	conn.Close()
}

// Pin is for cert A but the server has cert B (like a MITM) - must fail.
func TestDialRejectsWrongCert(t *testing.T) {
	certA := selfSignedCert(t)
	certB := selfSignedCert(t) // MITM cert
	addrB := listenWith(t, certB)

	_, err := Dial(addrB, false, fingerprintOf(certA))
	if err == nil {
		t.Fatal("expected Dial to reject a connection presenting a certificate that doesn't match the pin, but it succeeded")
	}
}

// Without a pin, insecure mode accepts any cert.
func TestDialInsecureWithoutPinAcceptsAnything(t *testing.T) {
	certB := selfSignedCert(t)
	addrB := listenWith(t, certB)

	conn, err := Dial(addrB, true, nil)
	if err != nil {
		t.Fatalf("expected insecure Dial with no pin to accept any cert, got: %v", err)
	}
	conn.Close()
}

func TestResolvePinSavesOnFirstUse(t *testing.T) {
	cert := selfSignedCert(t)
	addr := listenWith(t, cert)
	pinFile := filepath.Join(t.TempDir(), "known_server.pin")

	pin, err := ResolvePin(addr, pinFile)
	if err != nil {
		t.Fatalf("ResolvePin: %v", err)
	}
	if !bytes.Equal(pin, fingerprintOf(cert)) {
		t.Fatalf("returned pin doesn't match the server's actual cert fingerprint")
	}

	saved, err := os.ReadFile(pinFile)
	if err != nil {
		t.Fatalf("expected pin file to be written: %v", err)
	}
	decoded, err := hex.DecodeString(string(saved))
	if err != nil {
		t.Fatalf("saved pin file isn't valid hex: %v", err)
	}
	if !bytes.Equal(decoded, fingerprintOf(cert)) {
		t.Fatalf("saved pin file doesn't match the server's actual cert fingerprint")
	}
}

// If the pin file exists ResolvePin shouldn't connect at all.
func TestResolvePinReadsSavedFileWithoutRedialing(t *testing.T) {
	cert := selfSignedCert(t)
	pinFile := filepath.Join(t.TempDir(), "known_server.pin")
	if err := os.WriteFile(pinFile, []byte(hex.EncodeToString(fingerprintOf(cert))), 0600); err != nil {
		t.Fatalf("seed pin file: %v", err)
	}

	unreachable := "127.0.0.1:1" // nothing listens here
	pin, err := ResolvePin(unreachable, pinFile)
	if err != nil {
		t.Fatalf("expected ResolvePin to read the saved file without dialing, got: %v", err)
	}
	if !bytes.Equal(pin, fingerprintOf(cert)) {
		t.Fatalf("pin read back from file doesn't match what was saved")
	}
}

// After TOFU, a different cert must be rejected.
func TestResolvePinThenDialDetectsCertChange(t *testing.T) {
	certA := selfSignedCert(t)
	addrA := listenWith(t, certA)
	pinFile := filepath.Join(t.TempDir(), "known_server.pin")

	pin, err := ResolvePin(addrA, pinFile)
	if err != nil {
		t.Fatalf("ResolvePin (first use): %v", err)
	}

	certB := selfSignedCert(t)
	addrB := listenWith(t, certB)

	if _, err := Dial(addrB, false, pin); err == nil {
		t.Fatal("expected Dial to reject a certificate that changed after trust-on-first-use, but it succeeded")
	}
}
