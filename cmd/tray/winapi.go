package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"golang.org/x/sys/windows"
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

// systemExe is the full path of a program in System32. A bare name would
// be searched in PATH, which can contain user-writable folders.
func systemExe(rel string) string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		dir = `C:\Windows\System32`
	}
	return filepath.Join(dir, rel)
}

// windowsExe is the same for programs in the Windows folder.
func windowsExe(name string) string {
	dir, err := windows.GetWindowsDirectory()
	if err != nil {
		dir = `C:\Windows`
	}
	return filepath.Join(dir, name)
}

// isUnderDir reports whether path is root or inside it (paths compared
// without case, like Windows does).
func isUnderDir(path, root string) bool {
	if root == "" {
		return false
	}
	p := strings.ToLower(filepath.Clean(path)) + `\`
	r := strings.ToLower(strings.TrimRight(filepath.Clean(root), `\`)) + `\`
	return strings.HasPrefix(p, r)
}

// installWarnedFile marks that the folder warning was already shown for
// this folder, so it isn't repeated on every start.
const installWarnedFile = "tray-folder-warning-shown"

// warnIfNotInstalled warns once when tray.exe isn't in Program Files.
// The tray runs as admin and starts client.exe (which loads wintun.dll)
// from its own folder; in a user-writable folder any program without
// admin rights can replace those files and get admin on the next
// connect. Program Files is writable only by admins.
func warnIfNotInstalled() {
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		if dir, err := windows.KnownFolderPath(id, 0); err == nil && isUnderDir(exeDir, dir) {
			return
		}
	}
	logger.Println("warning: tray.exe is not in Program Files, client.exe and wintun.dll in", exeDir, "can be replaced by programs without admin rights")
	flag := filepath.Join(exeDir, installWarnedFile)
	if _, err := os.Stat(flag); err == nil {
		return
	}
	walk.MsgBox(mainWin, "splicertc",
		"tray.exe запущен не из Program Files, а из\n"+exeDir+"\n\n"+
			"Трей работает с правами администратора и запускает client.exe и wintun.dll из этой папки. "+
			"Если в неё может писать обычный пользователь (Загрузки, Рабочий стол, папка с исходниками), "+
			"любая программа без прав администратора может подменить эти файлы и получить права "+
			"администратора при следующем подключении.\n\n"+
			"Положи tray.exe, client.exe и wintun.dll в папку внутри Program Files.\n\n"+
			"Это предупреждение больше не будет показываться для этой папки.",
		walk.MsgBoxOK|walk.MsgBoxIconWarning)
	if err := os.WriteFile(flag, nil, 0644); err != nil {
		logger.Println("folder warning flag:", err)
	}
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
