//go:build linux

package transport

import (
	"log"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// Max unsent bytes the kernel keeps in the socket buffer. Without this
// Linux can buffer megabytes and our own queue can't reorder anything.
const notSentLowat = 16 * 1024

var (
	tuneOKOnce   sync.Once
	bbrWarnOnce  sync.Once
	lowatWarnOne sync.Once
)

// tuneSocket sets TCP_NOTSENT_LOWAT and BBR on the socket. BBR keeps
// the router queue smaller than the default CUBIC. Errors are only logged.
func tuneSocket(c *net.TCPConn) {
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		lowatErr := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, notSentLowat)
		if lowatErr != nil {
			lowatWarnOne.Do(func() {
				log.Printf("transport: TCP_NOTSENT_LOWAT unavailable (%v)", lowatErr)
			})
		}
		bbrErr := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
		if bbrErr != nil {
			bbrWarnOnce.Do(func() {
				log.Printf("transport: BBR unavailable (%v), run 'sudo modprobe tcp_bbr' on the host", bbrErr)
			})
		}
		if lowatErr == nil && bbrErr == nil {
			tuneOKOnce.Do(func() {
				log.Printf("transport: tunnel sockets use BBR + %d KB unsent-data cap", notSentLowat/1024)
			})
		}
	})
}
