// Command tray is a minimal Windows GUI wrapper around the existing
// client.exe + setup-vpn-route.ps1 flow (see README.md's "vpn" mode
// section): a small settings window for vpn_addr/client_key/
// game_processes plus a tray icon for Connect/Disconnect, instead of
// hand-editing client-config.json and juggling Administrator PowerShell
// windows. It does not reimplement any tunnel or routing logic itself —
// it spawns the same binaries run-vpn.ps1 already spawns and reuses the
// same, already-debugged setup-vpn-route.ps1 (invoked with
// -ExecutionPolicy Bypass so a friend's default execution policy can't
// block it), just from a GUI instead of a console.
//
// Expects client.exe, client-config.json, setup-vpn-route.ps1, and
// wintun.dll to sit next to this exe — the same layout as a manual
// checkout, so no separate packaging step is required yet (see
// IDEAS.md Track B for the eventual installer).
package main

import (
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"
)

const (
	connectTimeout = 20 * time.Second
	createNoWindow = 0x08000000
)

var (
	colorGray  = color.RGBA{R: 0x9a, G: 0x9a, B: 0x9a, A: 0xff}
	colorGreen = color.RGBA{R: 0x2e, G: 0xa0, B: 0x4e, A: 0xff}
	colorRed   = color.RGBA{R: 0xc0, G: 0x39, B: 0x2b, A: 0xff}

	iconGray, iconGreen, iconRed *walk.Icon
)

var (
	exeDir string
	logger *log.Logger

	mu        sync.Mutex
	clientCmd *exec.Cmd

	mainWin       *walk.MainWindow
	notifyIcon    *walk.NotifyIcon
	statusLabel   *walk.TextLabel
	vpnAddrEdit   *walk.LineEdit
	clientKeyEdit *walk.LineEdit
	gameProcEdit  *walk.LineEdit

	connectAction    *walk.Action
	disconnectAction *walk.Action
	connectBtn       *walk.PushButton
	disconnectBtn    *walk.PushButton
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
			fatalStartup("Нужны права администратора (для TUN-адаптера и маршрутов), но получить их не удалось: " + err.Error())
		}
		os.Exit(0)
	}

	if err := runApp(); err != nil {
		fatalStartup("ошибка запуска: " + err.Error())
	}
}

func runApp() error {
	var err error
	if iconGray, err = solidIcon(colorGray); err != nil {
		return fmt.Errorf("icon: %w", err)
	}
	if iconGreen, err = solidIcon(colorGreen); err != nil {
		return fmt.Errorf("icon: %w", err)
	}
	if iconRed, err = solidIcon(colorRed); err != nil {
		return fmt.Errorf("icon: %w", err)
	}

	if err := (MainWindow{
		AssignTo: &mainWin,
		Title:    "splicertc",
		MinSize:  Size{Width: 440, Height: 260},
		Visible:  false,
		Layout:   VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2},
				Children: []Widget{
					TextLabel{Text: "Адрес сервера (vpn_addr):"},
					LineEdit{AssignTo: &vpnAddrEdit, CueBanner: "1.2.3.4:587"},

					TextLabel{Text: "Приватный ключ (client_key):"},
					LineEdit{AssignTo: &clientKeyEdit, PasswordMode: true},

					TextLabel{Text: "Игровые процессы, через запятую:"},
					LineEdit{AssignTo: &gameProcEdit, CueBanner: "deadlock.exe (необязательно)"},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{Text: "Сохранить", OnClicked: onSave},
					HSpacer{},
					PushButton{AssignTo: &connectBtn, Text: "Подключиться", OnClicked: onWindowConnect},
					PushButton{AssignTo: &disconnectBtn, Text: "Отключиться", Enabled: false, OnClicked: func() { go disconnect() }},
				},
			},
			TextLabel{AssignTo: &statusLabel, Text: "Статус: отключено"},
		},
	}.Create()); err != nil {
		return fmt.Errorf("create window: %w", err)
	}

	mainWin.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		// Closing the window (the [X] button) just hides it — the app
		// keeps running in the tray. Only "Выход" in the tray menu
		// actually exits.
		*canceled = true
		mainWin.Hide()
	})

	ni, err := walk.NewNotifyIcon(mainWin)
	if err != nil {
		return fmt.Errorf("notify icon: %w", err)
	}
	notifyIcon = ni
	if err := ni.SetIcon(iconGray); err != nil {
		return fmt.Errorf("set icon: %w", err)
	}
	_ = ni.SetToolTip("splicertc — отключено")

	openAction := walk.NewAction()
	_ = openAction.SetText("Настройки")
	openAction.Triggered().Attach(func() {
		mainWin.Show()
		_ = mainWin.Activate()
	})
	_ = ni.ContextMenu().Actions().Add(openAction)
	_ = ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())

	connectAction = walk.NewAction()
	_ = connectAction.SetText("Подключиться")
	connectAction.Triggered().Attach(func() { go connect() })
	_ = ni.ContextMenu().Actions().Add(connectAction)

	disconnectAction = walk.NewAction()
	_ = disconnectAction.SetText("Отключиться")
	_ = disconnectAction.SetEnabled(false)
	disconnectAction.Triggered().Attach(func() { go disconnect() })
	_ = ni.ContextMenu().Actions().Add(disconnectAction)
	_ = ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())

	logAction := walk.NewAction()
	_ = logAction.SetText("Открыть журнал")
	logAction.Triggered().Attach(func() {
		_ = exec.Command("notepad.exe", filepath.Join(exeDir, "tray.log")).Start()
	})
	_ = ni.ContextMenu().Actions().Add(logAction)
	_ = ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())

	quitAction := walk.NewAction()
	_ = quitAction.SetText("Выход")
	quitAction.Triggered().Attach(func() {
		stopClient()
		walk.App().Exit(0)
	})
	_ = ni.ContextMenu().Actions().Add(quitAction)

	if err := ni.SetVisible(true); err != nil {
		return fmt.Errorf("show notify icon: %w", err)
	}

	loadConfigFields()
	if vpnAddrEdit.Text() == "" || clientKeyEdit.Text() == "" {
		// Nothing usable saved yet — open the window instead of hiding
		// behind a tray icon nobody knows to click yet.
		mainWin.Show()
	}

	mainWin.Run()
	return nil
}

// solidIcon draws a filled circle of c on a transparent 32x32 canvas —
// generated at runtime instead of shipping .ico assets, since
// walk.NewIconFromImage accepts a plain image.Image directly.
func solidIcon(c color.RGBA) (*walk.Icon, error) {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	cx, cy := float64(size)/2, float64(size)/2
	r := float64(size)/2 - 2
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			if dx*dx+dy*dy <= r*r {
				img.Set(x, y, c)
			}
		}
	}
	return walk.NewIconFromImage(img)
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

func configPath() string { return filepath.Join(exeDir, "client-config.json") }

// loadConfigFields prefills the window's fields from an existing
// client-config.json, if there is one. Missing file or unparseable
// content just leaves the fields empty — not fatal, the user can still
// fill them in and Save.
func loadConfigFields() {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		logger.Println("client-config.json: parse error:", err)
		return
	}
	if v, ok := m["vpn_addr"].(string); ok {
		_ = vpnAddrEdit.SetText(v)
	}
	if v, ok := m["client_key"].(string); ok {
		_ = clientKeyEdit.SetText(v)
	}
	if v, ok := m["game_processes"].([]interface{}); ok {
		parts := make([]string, 0, len(v))
		for _, p := range v {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		_ = gameProcEdit.SetText(strings.Join(parts, ", "))
	}
}

// saveConfigFields writes vpn_addr/client_key/game_processes into
// client-config.json, preserving every other field already in the file
// untouched (reads the existing JSON as a generic map first) — so
// fields this window doesn't expose (insecure, pin_file, vpn_tun_name,
// ...) survive a Save unchanged. If the file doesn't exist yet, seeds
// the same defaults client-config.example.json ships for vpn mode.
func saveConfigFields() error {
	m := map[string]interface{}{}
	if data, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	if len(m) == 0 {
		m = map[string]interface{}{
			"mode":         "vpn",
			"vpn_tun_name": "dormvpn0",
			"vpn_tun_mtu":  1400,
			"insecure":     true,
			"pin_file":     "known_server.pin",
		}
	}

	m["vpn_addr"] = vpnAddrEdit.Text()
	m["client_key"] = clientKeyEdit.Text()

	procsText := strings.TrimSpace(gameProcEdit.Text())
	if procsText == "" {
		delete(m, "game_processes")
	} else {
		var procs []string
		for _, p := range strings.Split(procsText, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				procs = append(procs, p)
			}
		}
		m["game_processes"] = procs
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), out, 0644)
}

func onSave() {
	if err := saveConfigFields(); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось сохранить конфиг: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	setStatus("настройки сохранены")
}

func onWindowConnect() {
	if err := saveConfigFields(); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось сохранить конфиг: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	go connect()
}

func setStatus(text string) {
	logger.Println("status:", text)
	if statusLabel != nil {
		_ = statusLabel.SetText("Статус: " + text)
	}
	if notifyIcon != nil {
		_ = notifyIcon.SetToolTip("splicertc — " + text)
	}
}

func setConnected(connected bool) {
	if connectAction != nil {
		_ = connectAction.SetEnabled(!connected)
	}
	if disconnectAction != nil {
		_ = disconnectAction.SetEnabled(connected)
	}
	if connectBtn != nil {
		connectBtn.SetEnabled(!connected)
	}
	if disconnectBtn != nil {
		disconnectBtn.SetEnabled(connected)
	}
}

func fail(text string) {
	logger.Println("error:", text)
	setStatus(text)
	if notifyIcon != nil {
		_ = notifyIcon.SetIcon(iconRed)
	}
	setConnected(false)
}

// connect spawns client.exe, waits for it to report the vpn channel is
// up, then runs the existing routing script — the exact two steps
// run-vpn.ps1 already performs, just driven from Go instead of a second
// PowerShell window.
func connect() {
	setConnected(false)
	setStatus("подключение...")
	if notifyIcon != nil {
		_ = notifyIcon.SetIcon(iconGray)
	}

	clientExe := filepath.Join(exeDir, "client.exe")
	cfgPath := configPath()
	scriptPath := filepath.Join(exeDir, "setup-vpn-route.ps1")
	for _, p := range []string{clientExe, cfgPath, scriptPath} {
		if _, err := os.Stat(p); err != nil {
			fail(filepath.Base(p) + " не найден рядом с tray.exe")
			return
		}
	}

	c := exec.Command(clientExe, "-config", cfgPath)
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
	if notifyIcon != nil {
		_ = notifyIcon.SetIcon(iconGreen)
	}
	setConnected(true)
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
	setStatus("отключение...")
	stopClient()
	setStatus("отключено")
	if notifyIcon != nil {
		_ = notifyIcon.SetIcon(iconGray)
	}
	setConnected(false)
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

// fatalStartup handles failures before the walk window/message loop
// exists (can't resolve our own exe path, can't elevate, can't create
// the window) — there's no console and no walk.MsgBox available yet, so
// this calls MessageBoxW directly.
func fatalStartup(text string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString("splicertc")
	m, _ := syscall.UTF16PtrFromString(text)
	const mbIconError = 0x10
	messageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), mbIconError)
	os.Exit(1)
}
