package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// The log is started over when it gets bigger than this (the previous
// one is kept as tray.log.old), so it doesn't grow forever.
const maxLogSize = 5 << 20

func setupLogger() {
	path := filepath.Join(exeDir, "tray.log")
	if st, err := os.Stat(path); err == nil && st.Size() > maxLogSize {
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// no log file, just don't log
		logger = log.New(io.Discard, "", log.LstdFlags)
		return
	}
	logger = log.New(f, "", log.LstdFlags)
}

// relaunchElevated starts this exe again as admin (UAC prompt). Admin is
// needed for the TUN adapter and routes.
func relaunchElevated(exe string) error {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")

	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	dir, err := syscall.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}

	const swShowNormal = 1
	ret, _, callErr := shellExecute.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0,
		uintptr(unsafe.Pointer(dir)),
		swShowNormal,
	)
	// > 32 means success
	if ret <= 32 {
		if ret == 5 {
			return fmt.Errorf("отказано в запросе прав администратора")
		}
		return fmt.Errorf("ShellExecute: код %d (%v)", ret, callErr)
	}
	return nil
}

// fatalStartup shows an error with MessageBoxW, used before the window exists.
func fatalStartup(text string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString("splicertc")
	m, _ := syscall.UTF16PtrFromString(text)
	const mbIconError = 0x10
	messageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), mbIconError)
	os.Exit(1)
}
