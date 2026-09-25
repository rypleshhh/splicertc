//go:build linux

package transport

import (
	"log"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// notSentLowat caps how many not-yet-transmitted bytes the kernel will
// hold in a tunnel socket's send buffer. Without it Linux autotunes that
// buffer up to several megabytes, and anything written behind a
// download sits in one big FIFO the tunnel's own scheduler
// (internal/sched) can't reorder. Doesn't limit in-flight (sent,
// unacknowledged) data, so throughput is unaffected. 16 KB is what
// Cloudflare uses for the same reason in HTTP/2 prioritization.
const notSentLowat = 16 * 1024

var (
	tuneOKOnce   sync.Once
	bbrWarnOnce  sync.Once
	lowatWarnOne sync.Once
)

// tuneSocket applies best-effort low-latency options:
//   - TCP_NOTSENT_LOWAT, see notSentLowat.
//   - BBR congestion control. The Linux default, CUBIC, keeps growing
//     its window until the bottleneck buffer overflows — it *fills* the
//     queue on the slowest link (the dorm connection), and every packet
//     of every connection through that link, multipath game paths
//     included, waits in it. BBR paces at the measured bottleneck rate
//     and keeps that queue near empty. Set per socket, so nothing else
//     on the host (e.g. a co-hosted Xray) is affected.
//
// Failures are logged once and otherwise ignored — the tunnel still
// works without either option, just with more queueing.
func tuneSocket(c *net.TCPConn) {
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		lowatErr := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, notSentLowat)
		if lowatErr != nil {
			lowatWarnOne.Do(func() {
				log.Printf("transport: TCP_NOTSENT_LOWAT unavailable (%v) — kernel send buffers stay unbounded", lowatErr)
			})
		}
		bbrErr := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
		if bbrErr != nil {
			bbrWarnOnce.Do(func() {
				log.Printf("transport: BBR unavailable (%v) — using the host's default congestion control; on the host run `sudo modprobe tcp_bbr` (and add tcp_bbr to /etc/modules-load.d/ to keep it after reboot)", bbrErr)
			})
		}
		if lowatErr == nil && bbrErr == nil {
			tuneOKOnce.Do(func() {
				log.Printf("transport: tunnel sockets use BBR + %d KB unsent-data cap", notSentLowat/1024)
			})
		}
	})
}
