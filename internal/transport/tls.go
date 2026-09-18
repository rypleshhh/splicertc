// Package transport handles the TLS dial/listen side of the tunnel.
// Later this is where utls fingerprinting (MVP step 4) will slot in —
// for now it's plain crypto/tls so we can validate the pipe end-to-end.
package transport

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
)

// Listen binds addr and returns a listener that terminates TLS 1.3
// using the given cert/key pair (PEM files on disk). Every accepted
// connection has Nagle's algorithm disabled — see Dial's comment.
func Listen(addr, certFile, keyFile string) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		return tls.NewListener(ln, cfg), nil // shouldn't happen for the "tcp" network, but don't crash if it does
	}
	return tls.NewListener(noDelayListener{tcpLn}, cfg), nil
}

// noDelayListener disables Nagle's algorithm on every accepted
// connection before it's handed to the TLS layer.
type noDelayListener struct {
	*net.TCPListener
}

func (l noDelayListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetNoDelay(true)
	return conn, nil
}

// Dial opens a TLS connection to addr, with Nagle's algorithm disabled
// on the underlying TCP connection. This project's traffic is bursts of
// small packets (game actions, individually-framed tunneled packets) —
// Nagle coalescing them to fill a fuller segment trades throughput
// efficiency for latency we can't afford, exactly backwards from what a
// latency-sensitive tunnel wants. Every real-time protocol disables it
// for the same reason; tls.Dial doesn't expose the underlying
// net.TCPConn to configure this, so the connection is built by hand.
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
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

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

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// ResolvePin implements trust-on-first-use (TOFU) pinning, the same
// model ssh's known_hosts uses: if pinFile already holds a saved
// fingerprint, it's read back and returned — from then on this is
// exactly as strict as a manually-entered pin. If pinFile doesn't exist
// yet, this dials addr once, accepts whatever certificate the server
// presents (the same exposure insecureSkipVerify:true has, but only for
// this one bootstrap connection), saves its fingerprint to pinFile, and
// returns it. Every connection after this point — including the rest of
// the caller's current run — is then pinned to that fingerprint.
//
// To force re-trusting a server (e.g. after regenerating its cert),
// delete pinFile; the next call repeats the bootstrap step.
func ResolvePin(addr, pinFile string) ([]byte, error) {
	if data, err := os.ReadFile(pinFile); err == nil {
		pin, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("pin file %s: invalid hex: %w", pinFile, err)
		}
		return pin, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read pin file %s: %w", pinFile, err)
	}

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("trust-on-first-use dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	var fingerprint []byte
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			fingerprint = sum[:]
			return nil
		},
	}
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("trust-on-first-use handshake with %s: %w", addr, err)
	}

	if err := os.WriteFile(pinFile, []byte(hex.EncodeToString(fingerprint)), 0600); err != nil {
		return nil, fmt.Errorf("save pin file %s: %w", pinFile, err)
	}
	return fingerprint, nil
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
