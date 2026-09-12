// Package proto defines the minimal framing the tunnel itself uses to tell
// the server which host:port to dial, before relaying starts on a stream.
// This is separate from the SOCKS5 protocol the client speaks to the app —
// SOCKS5 terminates at the client edge, this is what carries the target
// across the tunnel once the client has already parsed it out.
package proto

import (
	"encoding/binary"
	"io"
)

// WriteTarget sends a length-prefixed "host:port" string.
func WriteTarget(w io.Writer, target string) error {
	buf := make([]byte, 2+len(target))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(target)))
	copy(buf[2:], target)
	_, err := w.Write(buf)
	return err
}

// ReadTarget reads back what WriteTarget sent.
func ReadTarget(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
