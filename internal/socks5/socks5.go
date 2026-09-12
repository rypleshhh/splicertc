// Package socks5 implements just enough of the SOCKS5 protocol (RFC 1928)
// to sit at the client edge: no-auth handshake, CONNECT command only.
// This is what apps like Steam/curl/a browser configured to use a SOCKS5
// proxy will actually speak to us.
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	version5 = 0x05

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Handshake performs SOCKS5 method negotiation, always selecting
// "no authentication required" — dev-stage simplification, revisit
// if the tunnel ever needs to gate who can use the local proxy.
func Handshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != version5 {
		return fmt.Errorf("unsupported socks version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	_, err := conn.Write([]byte{version5, 0x00})
	return err
}

// ReadRequest parses a SOCKS5 CONNECT request and returns "host:port".
func ReadRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != version5 {
		return "", fmt.Errorf("unsupported socks version: %d", header[0])
	}
	if header[1] != cmdConnect {
		return "", fmt.Errorf("unsupported command %d (only CONNECT is implemented)", header[1])
	}

	var host string
	switch header[3] {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)

	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	default:
		return "", fmt.Errorf("unsupported address type %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// WriteReply sends the SOCKS5 reply. Bound address/port are zeroed out —
// fine for a CONNECT-only proxy, most clients never inspect them.
func WriteReply(conn net.Conn, success bool) error {
	rep := byte(0x00)
	if !success {
		rep = 0x01 // general failure — good enough at this stage
	}
	reply := []byte{version5, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}
