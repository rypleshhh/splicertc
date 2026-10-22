//go:build !windows

package proto

import "syscall"

var (
	errRefused         = syscall.ECONNREFUSED
	errNetUnreachable  = syscall.ENETUNREACH
	errHostUnreachable = syscall.EHOSTUNREACH
)
