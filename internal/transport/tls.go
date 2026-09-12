// Package transport handles the TLS dial/listen side of the tunnel.
// Later this is where utls fingerprinting (MVP step 4) will slot in —
// for now it's plain crypto/tls so we can validate the pipe end-to-end.
package transport

import (
	"crypto/tls"
	"net"
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
// insecureSkipVerify exists only for local testing against our throwaway
// self-signed dev cert — real cert validation (or Reality-style pinning)
// comes back once we're past the loopback stage.
func Dial(addr string, insecureSkipVerify bool) (net.Conn, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecureSkipVerify,
	}
	return tls.Dial("tcp", addr, cfg)
}
