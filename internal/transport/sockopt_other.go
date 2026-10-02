//go:build !linux

package transport

import "net"

// Not supported outside Linux.
func tuneSocket(*net.TCPConn) {}
