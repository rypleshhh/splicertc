//go:build windows

// Package procmap finds which process owns a local UDP port, using the
// Windows IP Helper API. Used to detect game traffic by process name.
package procmap

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedUDPTable = modIphlpapi.NewProc("GetExtendedUdpTable")

	modKernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = modKernel32.NewProc("OpenProcess")
	procCloseHandle                = modKernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	afINET                         = 2 // AF_INET
	udpTableOwnerPID               = 1 // UDP_TABLE_OWNER_PID
	errInsufficientBuffer          = 122
	processQueryLimitedInformation = 0x1000
)

// Table maps local UDP port -> process name. Call Refresh to update it.
type Table struct {
	mu     sync.RWMutex
	byPort map[uint16]string // e.g. "deadlock.exe"
}

func New() *Table {
	return &Table{byPort: make(map[uint16]string)}
}

// ProcessForUDPPort returns the lowercase exe name for the port.
func (t *Table) ProcessForUDPPort(port uint16) (name string, ok bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	name, ok = t.byPort[port]
	return
}

// Refresh reloads the UDP table from Windows.
func (t *Table) Refresh() error {
	buf, err := getExtendedUDPTable()
	if err != nil {
		return err
	}
	if len(buf) < 4 {
		return fmt.Errorf("procmap: unexpectedly short UDP table (%d bytes)", len(buf))
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	const rowSize = 12 // MIB_UDPROW_OWNER_PID: addr, port, pid

	byPort := make(map[uint16]string, numEntries)
	pidNames := make(map[uint32]string)

	off := 4
	for i := uint32(0); i < numEntries; i++ {
		if off+rowSize > len(buf) {
			break
		}
		rawPort := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		pid := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		off += rowSize

		// port is in network byte order
		p16 := uint16(rawPort & 0xFFFF)
		port := (p16 >> 8) | (p16 << 8)

		name, ok := pidNames[pid]
		if !ok {
			name = processName(pid)
			pidNames[pid] = name
		}
		if name != "" {
			byPort[port] = name
		}
	}

	t.mu.Lock()
	t.byPort = byPort
	t.mu.Unlock()
	return nil
}

// getExtendedUDPTable calls the API twice: first to get the size.
func getExtendedUDPTable() ([]byte, error) {
	var size uint32
	r1, _, _ := procGetExtendedUDPTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 0, afINET, udpTableOwnerPID, 0)
	if r1 != errInsufficientBuffer {
		if r1 == 0 {
			return nil, fmt.Errorf("procmap: GetExtendedUdpTable size probe unexpectedly succeeded with no buffer")
		}
		return nil, fmt.Errorf("procmap: GetExtendedUdpTable size probe failed: %d", r1)
	}

	buf := make([]byte, size)
	r1, _, _ = procGetExtendedUDPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afINET, udpTableOwnerPID, 0)
	if r1 != 0 {
		return nil, fmt.Errorf("procmap: GetExtendedUdpTable failed: %d", r1)
	}
	return buf, nil
}

// processName returns "" if the process can't be opened (system process,
// or it already exited).
func processName(pid uint32) string {
	h, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer procCloseHandle.Call(h)

	buf := make([]uint16, 260) // MAX_PATH
	size := uint32(len(buf))
	r1, _, _ := procQueryFullProcessImageNameW.Call(
		h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r1 == 0 {
		return ""
	}
	full := syscall.UTF16ToString(buf[:size])
	return strings.ToLower(filepath.Base(full))
}
