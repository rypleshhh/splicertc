// Package transport handles TLS dial/listen for the tunnel.
// TODO: utls fingerprinting.
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

// Listen starts a TLS 1.3 listener with the given cert/key files.
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
		return tls.NewListener(ln, cfg), nil
	}
	return tls.NewListener(noDelayListener{tcpLn}, cfg), nil
}

// noDelayListener turns off Nagle on accepted connections.
type noDelayListener struct {
	*net.TCPListener
}

func (l noDelayListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetNoDelay(true)
	tuneSocket(conn)
	return conn, nil
}

// Dial connects with TLS. Nagle is disabled because we send lots of
// small packets and don't want them delayed (tls.Dial doesn't let us
// set it, so the TCP connection is created manually).
//
// If pin is set, the server cert's SHA-256 must match it, otherwise the
// handshake fails. insecureSkipVerify is only used when pin is nil.
func Dial(addr string, insecureSkipVerify bool, pin []byte) (net.Conn, error) {
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		tuneSocket(tcpConn)
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if pin != nil {
		// we check the cert ourselves below
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

// ResolvePin does trust-on-first-use, like ssh known_hosts. If pinFile
// exists, the saved fingerprint is returned. Otherwise it connects once,
// saves the server's cert fingerprint to pinFile and returns it.
// Delete pinFile to trust a new server cert.
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

// LoadCertFingerprint returns SHA-256 of the certificate in a PEM file.
// The server prints it on startup so it can be used as server_pin.
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
