// Package proto is what goes over one stream of the reliable channel:
// the client sends the target "host:port", the server answers with one
// status byte, then bytes are copied both ways (Relay).
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Status codes are the SOCKS5 reply codes (RFC 1928), so the client can
// pass them to the application as they are.
const (
	StatusOK              byte = 0x00
	StatusFailure         byte = 0x01
	StatusNotAllowed      byte = 0x02
	StatusNetUnreachable  byte = 0x03
	StatusHostUnreachable byte = 0x04
	StatusRefused         byte = 0x05
)

// ErrNotAllowed marks a target refused by the server's policy.
var ErrNotAllowed = errors.New("target not allowed")

// maxTarget fits the 16 bit length; a real "host:port" is under 300 bytes.
const maxTarget = 1<<16 - 1

// WriteTarget sends a length-prefixed "host:port" string.
func WriteTarget(w io.Writer, target string) error {
	if len(target) > maxTarget {
		return fmt.Errorf("target too long (%d bytes)", len(target))
	}
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

// DialStatus turns a dial error into a status code.
func DialStatus(err error) byte {
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case err == nil:
		return StatusOK
	case errors.Is(err, ErrNotAllowed):
		return StatusNotAllowed
	case errors.Is(err, errRefused):
		return StatusRefused
	case errors.Is(err, errNetUnreachable):
		return StatusNetUnreachable
	case errors.Is(err, errHostUnreachable), errors.As(err, &dnsErr):
		return StatusHostUnreachable
	case errors.As(err, &netErr) && netErr.Timeout():
		return StatusHostUnreachable
	default:
		return StatusFailure
	}
}

// After one direction of a relay is done, the other one gets this long
// to finish (half-close: e.g. the client sent everything and waits for
// the answer).
const relayDrainTimeout = time.Minute

type closeWriter interface{ CloseWrite() error }

// Relay copies both ways. When one side stops sending, only the write
// half of the other side is closed (if it supports CloseWrite), so
// protocols that half-close and wait for the answer keep working. Both
// connections are closed when Relay returns.
func Relay(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	done := make(chan struct{}, 2)
	copyHalf := func(dst io.WriteCloser, src io.Reader) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	wg.Add(2)
	go copyHalf(a, b)
	go copyHalf(b, a)

	<-done
	select {
	case <-done:
	case <-time.After(relayDrainTimeout):
	}
	a.Close()
	b.Close()
	wg.Wait()
}
