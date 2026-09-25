//go:build !linux

package transport

import "net"

// tuneSocket is Linux-only (TCP_NOTSENT_LOWAT and per-socket BBR have no
// portable equivalent). On Windows the client relies on the stack's own
// send-backlog autotuning; the server, where downloads originate, is
// always Linux.
func tuneSocket(*net.TCPConn) {}
