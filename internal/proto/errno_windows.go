package proto

import "golang.org/x/sys/windows"

// Winsock has its own error numbers.
var (
	errRefused         = windows.WSAECONNREFUSED
	errNetUnreachable  = windows.WSAENETUNREACH
	errHostUnreachable = windows.WSAEHOSTUNREACH
)
