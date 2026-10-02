// Package proto sends the target host:port to the server at the start
// of a stream.
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
