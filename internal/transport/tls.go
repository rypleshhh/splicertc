// Package transport handles the TLS dial/listen side of the tunnel.
// Later this is where utls fingerprinting (MVP step 4) will slot in —
// for now it's plain crypto/tls so we can validate the pipe end-to-end.
package transport

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
)

// Listen binds addr and returns a listener that terminates TLS 1.3
// using the given cert/key pair (PEM files on disk).
func Listen(addr, certFile, keyFile string) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	return tls.Listen("tcp", addr, cfg)
}

// Dial opens a TLS connection to addr.
//
// If pin is non-nil, the peer's certificate must match it exactly
// (SHA-256 of the leaf certificate's DER bytes) or the handshake is
// aborted; insecureSkipVerify is then moot — a specific pinned
// certificate is strictly stronger than either CA validation or no
// validation at all — and only applies when pin is nil. Without a pin,
// insecureSkipVerify:true (the project's throwaway self-signed dev
// cert) accepts *any* certificate from *anyone*, which lets a
// TLS-intercepting middlebox terminate the connection itself and read
// everything; pinning closes that, since TLS 1.3 (already the minimum
// version here) requires proving possession of the certificate's
// private key to complete the handshake — a party without that key
// cannot complete a handshake presenting the pinned cert, period.
func Dial(addr string, insecureSkipVerify bool, pin []byte) (net.Conn, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if pin != nil {
		// We do our own verification in VerifyPeerCertificate below,
		// which is why the default verification is skipped here.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], pin) {
				return fmt.Errorf("server certificate does not match pinned fingerprint")
			}
			return nil
		}
	} else {
		cfg.InsecureSkipVerify = insecureSkipVerify
	}
	return tls.Dial("tcp", addr, cfg)
}

// LoadCertFingerprint reads a PEM certificate file and returns the
// SHA-256 of its leaf certificate's DER bytes — the value to print at
// server startup for the user to copy into the client's server_pin
// config field, and the value Dial's pin parameter is compared against.
func LoadCertFingerprint(certFile string) ([]byte, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read cert file: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate block found", certFile)
	}
	sum := sha256.Sum256(block.Bytes)
	return sum[:], nil
}
