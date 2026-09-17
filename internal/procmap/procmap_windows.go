//go:build windows

// Package procmap answers one question: which process owns a given
// local UDP port, right now. Used to classify captured TUN traffic by
// its actual source application (e.g. a game) instead of guessing by
// destination IP range, which drifts as services move their infra.
//
// Windows-only — this is the client's own OS, and the whole reason this
// works is Windows already tracks (port -> owning PID) for us via the
// IP Helper API; nothing needs re-deriving from scratch.
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
	udpTableOwnerPID                = 1 // UDP_TABLE_OWNER_PID
	errInsufficientBuffer           = 122
	processQueryLimitedInformation  = 0x1000
)

// Table is a point-in-time snapshot of "local UDP port -> owning
// process basename", refreshed on demand. Refresh-driven by the caller
// rather than self-polling in a goroutine — simpler to test, and lets
// the caller pace refreshes against however fresh it actually needs the
// data (a fast-moving TUN capture loop doesn't need a syscall per
// packet).
type Table struct {
	mu     sync.RWMutex
	byPort map[uint16]string // lowercase process basename, e.g. "deadlock.exe"
}

// New returns an empty Table — call Refresh before the first lookup.
func New() *Table {
	return &Table{byPort: make(map[uint16]string)}
}

// ProcessForUDPPort reports the lowercase basename of the process that
// owned local UDP port as of the last Refresh, e.g. "deadlock.exe".
func (t *Table) ProcessForUDPPort(port uint16) (name string, ok bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	name, ok = t.byPort[port]
	return
}

// Refresh re-reads the OS's live UDP socket table via GetExtendedUdpTable
// and rebuilds the port->process map.
func (t *Table) Refresh() error {
	buf, err := getExtendedUDPTable()
	if err != nil {
		return err
	}
	if len(buf) < 4 {
		return fmt.Errorf("procmap: unexpectedly short UDP table (%d bytes)", len(buf))
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	const rowSize = 12 // MIB_UDPROW_OWNER_PID: dwLocalAddr + dwLocalPort + dwOwningPid, all DWORD, no padding

	byPort := make(map[uint16]string, numEntries)
	pidNames := make(map[uint32]string)

	off := 4
	for i := uint32(0); i < numEntries; i++ {
		if off+rowSize > len(buf) {
			break // defensive: malformed/truncated table — stop, don't panic
		}
		rawPort := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		pid := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		off += rowSize

		// dwLocalPort's low 16 bits are in network (big-endian) byte
		// order regardless of host endianness — a well-known Windows IP
		// Helper API gotcha. Swap to host order before using it.
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

// getExtendedUDPTable calls GetExtendedUdpTable with the standard
// "probe for the required size, allocate, call again" two-pass pattern
// every IP Helper API table function uses.
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

// processName resolves pid to its executable's lowercase basename, or
// "" if it can't be opened/queried — e.g. a system process we don't
// have rights to, or it exited between the table snapshot and this
// lookup. Either way, skipping that one entry is correct; erroring the
// whole refresh over one unreadable process is not.
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
