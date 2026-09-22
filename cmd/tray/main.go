// Command tray is a minimal Windows system-tray wrapper around the
// existing client.exe + setup-vpn-route.ps1 flow (see README.md's "vpn"
// mode section) — Connect/Disconnect from a tray icon instead of
// juggling Administrator PowerShell windows and manual routing
// commands by hand. It does not reimplement any tunnel or routing
// logic itself: it spawns the same binaries run-vpn.ps1 already spawns
// and reuses the same, already-debugged setup-vpn-route.ps1 (invoked
// with -ExecutionPolicy Bypass so a friend's default execution policy
// can't block it), just from a GUI instead of a console.
//
// Expects client.exe, client-config.json, setup-vpn-route.ps1, and
// wintun.dll to sit next to this exe — the same layout as a manual
// checkout, so no separate packaging step is required yet (see
// IDEAS.md Track B for the eventual installer).
package main

import (
	_ "embed"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
)

//go:embed icons/disconnected.ico
var iconDisconnected []byte

//go:embed icons/connected.ico
var iconConnected []byte

//go:embed icons/error.ico
var iconErr []byte

const (
	connectTimeout = 20 * time.Second
	createNoWindow = 0x08000000
)

var (
	exeDir string
	logger *log.Logger

	mu        sync.Mutex
	clientCmd *exec.Cmd

	mStatus     *systray.MenuItem
	mConnect    *systray.MenuItem
	mDisconnect *systray.MenuItem
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		fatalStartup("resolve own exe path: " + err.Error())
	}
	exeDir = filepath.Dir(exe)
	setupLogger()

	if !windows.GetCurrentProcessToken().IsElevated() {
		if err := relaunchElevated(exe); err != nil {
			messageBox("splicertc", "Нужны права администратора (для TUN-адаптера и маршрутов), но получить их не удалось: "+err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	systray.Run(onReady, onExit)
}

func onReady() {
	systray.SetIcon(iconDisconnected)
	systray.SetTooltip("splicertc — отключено")

	mStatus = systray.AddMenuItem("Статус: отключено", "")
	mStatus.Disable()
	systray.AddSeparator()
	mConnect = systray.AddMenuItem("Подключиться", "Поднять туннель и настроить маршруты")
	mDisconnect = systray.AddMenuItem("Отключиться", "Остановить туннель")
	mDisconnect.Disable()
	systray.AddSeparator()
	mLog := systray.AddMenuItem("Открыть журнал", "Открыть tray.log в Блокноте")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Выход", "Закрыть splicertc")

	go func() {
		for {
			select {
			case <-mConnect.ClickedCh:
				go connect()
			case <-mDisconnect.ClickedCh:
				go disconnect()
			case <-mLog.ClickedCh:
				exec.Command("notepad.exe", filepath.Join(exeDir, "tray.log")).Start()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func onExit() {
	stopClient()
}

func setupLogger() {
	f, err := os.OpenFile(filepath.Join(exeDir, "tray.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// Can't write the log file — fall back to discarding rather than
		// crashing a GUI app that has nowhere to show the error anyway.
		logger = log.New(io.Discard, "", log.LstdFlags)
		return
	}
	logger = log.New(f, "", log.LstdFlags)
}

func setStatus(text string) {
	logger.Println("status:", text)
	if mStatus != nil {
		mStatus.SetTitle("Статус: " + text)
	}
	systray.SetTooltip("splicertc — " + text)
}

func fail(text string) {
	logger.Println("error:", text)
	setStatus(text)
	systray.SetIcon(iconErr)
	if mConnect != nil {
		mConnect.Enable()
	}
	if mDisconnect != nil {
		mDisconnect.Disable()
	}
}

// connect spawns client.exe, waits for it to report the vpn channel is
// up, then runs the existing routing script — the exact two steps
// run-vpn.ps1 already performs, just driven from Go instead of a second
// PowerShell window.
func connect() {
	mConnect.Disable()
	setStatus("подключение...")
	systray.SetIcon(iconDisconnected)

	clientExe := filepath.Join(exeDir, "client.exe")
	configPath := filepath.Join(exeDir, "client-config.json")
	scriptPath := filepath.Join(exeDir, "setup-vpn-route.ps1")
	for _, p := range []string{clientExe, configPath, scriptPath} {
		if _, err := os.Stat(p); err != nil {
			fail(filepath.Base(p) + " не найден рядом с tray.exe")
			return
		}
	}

	c := exec.Command(clientExe, "-config", configPath)
	c.Dir = exeDir
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	stdout, err := c.StdoutPipe()
	if err != nil {
		fail("client.exe: " + err.Error())
		return
	}
	stderr, err := c.StderrPipe()
	if err != nil {
		fail("client.exe: " + err.Error())
		return
	}
	if err := c.Start(); err != nil {
		fail("не удалось запустить client.exe: " + err.Error())
		return
	}

	mu.Lock()
	clientCmd = c
	mu.Unlock()

	connectedCh := make(chan bool, 1)
	go scanForConnected(stdout, connectedCh)
	go scanForConnected(stderr, connectedCh)
	go func() {
		// If client.exe exits later (crash, kicked by another peer,
		// network drop — see IDEAS.md P1 #4, this isn't fixed yet), the
		// tray shouldn't keep claiming to be connected.
		err := c.Wait()
		mu.Lock()
		stillOurs := clientCmd == c
		if stillOurs {
			clientCmd = nil
		}
		mu.Unlock()
		if stillOurs {
			logger.Println("client.exe exited:", err)
			fail("клиент неожиданно завершился — смотри tray.log")
		}
	}()

	select {
	case ok := <-connectedCh:
		if !ok {
			return // scanForConnected already called fail()
		}
	case <-time.After(connectTimeout):
		fail("клиент не подключился за " + connectTimeout.String() + " — смотри tray.log")
		stopClient()
		return
	}

	setStatus("настройка маршрутов...")
	rc := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	rc.Dir = exeDir
	rc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := rc.CombinedOutput()
	logger.Println("setup-vpn-route.ps1 output:\n" + string(out))
	if err != nil {
		fail("не удалось настроить маршрутизацию — смотри tray.log")
		stopClient()
		return
	}

	setStatus("подключено")
	systray.SetIcon(iconConnected)
	mDisconnect.Enable()
}

// scanForConnected copies r into the log file line by line and reports
// true on connectedCh the moment it sees the "connected to vpn channel"
// line client.exe logs on success (cmd/client/vpn.go). Reports false if
// the stream ends first without ever seeing it (client exited early).
func scanForConnected(r io.Reader, connectedCh chan<- bool) {
	buf := make([]byte, 4096)
	var line []byte
	seen := false
	for {
		n, err := r.Read(buf)
		if n > 0 {
			for _, b := range buf[:n] {
				if b == '\n' {
					logger.Println("client:", string(line))
					if !seen && containsConnected(line) {
						seen = true
						select {
						case connectedCh <- true:
						default:
						}
					}
					line = line[:0]
				} else {
					line = append(line, b)
				}
			}
		}
		if err != nil {
			if len(line) > 0 {
				logger.Println("client:", string(line))
			}
			if !seen {
				select {
				case connectedCh <- false:
				default:
				}
			}
			return
		}
	}
}

func containsConnected(line []byte) bool {
	const marker = "connected to vpn channel"
	return len(line) >= len(marker) && indexOf(string(line), marker) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func disconnect() {
	mDisconnect.Disable()
	setStatus("отключение...")
	stopClient()
	setStatus("отключено")
	systray.SetIcon(iconDisconnected)
	mConnect.Enable()
}

func stopClient() {
	mu.Lock()
	c := clientCmd
	clientCmd = nil
	mu.Unlock()
	if c == nil || c.Process == nil {
		return
	}
	// Killing client.exe destroys its TUN adapter as a side effect of
	// the process exiting (same behavior run-vpn.ps1 already relies on
	// for Ctrl+C — see its header comment); Windows then drops routes
	// bound to the now-gone adapter on its own. The one thing that can
	// be left behind is the harmless anti-loop host route, cleaned up
	// automatically by setup-vpn-route.ps1's own idempotent cleanup step
	// on the next Connect.
	//
	// No explicit Wait() here on purpose: connect() already has a
	// background goroutine blocked on c.Wait() for this same process
	// (to notice an unexpected exit) — calling Wait() a second time
	// concurrently isn't something exec.Cmd promises is safe. clientCmd
	// was already cleared above, so that goroutine's stillOurs check
	// will correctly see this as an expected exit and stay quiet.
	_ = c.Process.Kill()
}

// relaunchElevated re-starts this same exe with a UAC prompt (the
// "runas" verb) and lets the caller exit — TUN creation and route
// changes both need Administrator, and a GUI app should ask for that
// itself instead of expecting a friend to know to right-click "Run as
// administrator".
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
	// ShellExecute returns a value > 32 on success; anything else is an
	// error code (e.g. the user clicked "No" on the UAC prompt).
	if ret <= 32 {
		if ret == 5 {
			return fmt.Errorf("отказано в запросе прав администратора")
		}
		return fmt.Errorf("ShellExecute: код %d (%v)", ret, callErr)
	}
	return nil
}

func messageBox(title, text string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	const mbIconError = 0x10
	messageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), mbIconError)
}

// fatalStartup handles the narrow case where we can't even figure out
// our own exe path (so setupLogger has nowhere to write) — show a
// message box, since there's no console to print to.
func fatalStartup(text string) {
	messageBox("splicertc", text)
	os.Exit(1)
}
