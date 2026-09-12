package transport

import (
	"crypto/tls"
	"net"
)

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

func Dial(addr string, insecureSkipVerify bool) (net.Conn, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecureSkipVerify,
	}
	return tls.Dial("tcp", addr, cfg)
}
