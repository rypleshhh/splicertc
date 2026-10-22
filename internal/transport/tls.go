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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
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

// DialTimeout limits both the TCP connect and the TLS handshake.
const DialTimeout = 10 * time.Second

// ErrPinMismatch means the server cert is not the pinned one: the cert
// was regenerated (delete the pin file / update server_pin) or it's not
// our server at all.
var ErrPinMismatch = errors.New("server certificate does not match pinned fingerprint")

// DialConfig says how the client checks the server.
type DialConfig struct {
	// ServerName is sent as SNI and, without Pin, is the name the
	// certificate must be valid for (a normal CA certificate, e.g. Let's
	// Encrypt). Empty means the host part of the address.
	ServerName string
	// Pin is the SHA-256 of the server certificate. When set, only the
	// pin is checked (self-signed certificates work).
	Pin []byte
	// Insecure accepts any certificate when there's no pin. Tests only.
	Insecure bool
}

// Dial connects with TLS. Nagle is disabled because we send lots of
// small packets and don't want them delayed (tls.Dial doesn't let us
// set it, so the TCP connection is created manually).
func Dial(addr string, dc DialConfig) (net.Conn, error) {
	rawConn, err := net.DialTimeout("tcp", addr, DialTimeout)
	if err != nil {
		return nil, err
	}
	_ = rawConn.SetDeadline(time.Now().Add(DialTimeout))
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		tuneSocket(tcpConn)
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: dc.ServerName}
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host // Go doesn't send an IP as SNI, but checks it against the cert
		}
	}
	switch {
	case dc.Pin != nil:
		// the chain isn't checked, only the fingerprint below
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], dc.Pin) {
				return ErrPinMismatch
			}
			return nil
		}
	case dc.Insecure:
		cfg.InsecureSkipVerify = true
	}

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	_ = rawConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// ParsePin decodes a hex SHA-256 fingerprint (server_pin, pin file).
func ParsePin(s string) ([]byte, error) {
	pin, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(pin) != sha256.Size {
		return nil, fmt.Errorf("expected %d bytes (SHA-256), got %d", sha256.Size, len(pin))
	}
	return pin, nil
}

// tcpConnOf returns the TCP connection under c (c can be a *tls.Conn).
func tcpConnOf(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	tcp, _ := c.(*net.TCPConn)
	return tcp
}

// SetSendBuffer sets SO_SNDBUF. Useful for low-rate connections where we
// don't want old data piling up in the kernel when the path is stuck.
func SetSendBuffer(c net.Conn, bytes int) {
	if tcp := tcpConnOf(c); tcp != nil {
		_ = tcp.SetWriteBuffer(bytes)
	}
}

// SetNotSentLowat overrides the default unsent-data limit (Linux only).
func SetNotSentLowat(c net.Conn, bytes int) {
	if tcp := tcpConnOf(c); tcp != nil {
		setNotSentLowat(tcp, bytes)
	}
}

// ResolvePin does trust-on-first-use, like ssh known_hosts. If pinFile
// exists, the saved fingerprint is returned. Otherwise it connects once,
// saves the server's cert fingerprint to pinFile and returns it.
// Delete pinFile to trust a new server cert.
func ResolvePin(addr, serverName, pinFile string) ([]byte, error) {
	if data, err := os.ReadFile(pinFile); err == nil {
		pin, err := ParsePin(string(data))
		if err != nil {
			return nil, fmt.Errorf("pin file %s: %w", pinFile, err)
		}
		return pin, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read pin file %s: %w", pinFile, err)
	}

	rawConn, err := net.DialTimeout("tcp", addr, DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("trust-on-first-use dial %s: %w", addr, err)
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(DialTimeout))

	var fingerprint []byte
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
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

	if err := writeFileAtomic(pinFile, []byte(hex.EncodeToString(fingerprint)), 0600); err != nil {
		return nil, fmt.Errorf("save pin file %s: %w", pinFile, err)
	}
	return fingerprint, nil
}

// writeFileAtomic writes to a temp file and renames it, so a crash in the
// middle never leaves a half-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
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
