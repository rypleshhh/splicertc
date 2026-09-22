// Command tray is a minimal Windows GUI wrapper around the existing
// client.exe + setup-vpn-route.ps1 flow (see README.md's "vpn" mode
// section): a small, dark-themed window listing named connections
// (server address + client key + optional game process list per name)
// plus a tray icon for Connect/Disconnect, instead of hand-editing
// client-config.json and juggling Administrator PowerShell windows. It
// does not reimplement any tunnel or routing logic itself — it spawns
// the same binaries run-vpn.ps1 already spawns and reuses the same,
// already-debugged setup-vpn-route.ps1 (invoked with -ExecutionPolicy
// Bypass so a friend's default execution policy can't block it), just
// from a GUI instead of a console.
//
// Named connections live in connections.json next to the exe; the
// selected one gets compiled into client-config.json (the file
// client.exe actually reads) right before Connect. Expects client.exe,
// setup-vpn-route.ps1, and wintun.dll to sit next to this exe too — the
// same layout as a manual checkout, so no separate packaging step is
// required yet (see IDEAS.md Track B for the eventual installer).
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
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/transport"
)

const (
	connectTimeout = 20 * time.Second
	createNoWindow = 0x08000000
)

var (
	colorIconGray  = color.RGBA{R: 0x9a, G: 0x9a, B: 0x9a, A: 0xff}
	colorIconGreen = color.RGBA{R: 0x2e, G: 0xa0, B: 0x4e, A: 0xff}
	colorIconRed   = color.RGBA{R: 0xc0, G: 0x39, B: 0x2b, A: 0xff}

	iconGray, iconGreen, iconRed *walk.Icon

	// Dark theme palette — deliberately simple (three flat colors), since
	// walk's classic Win32 controls don't support much beyond
	// background/text color short of full owner-drawing.
	darkWindowBg = walk.RGB(0x1e, 0x1e, 0x1e)
	darkPanelBg  = walk.RGB(0x25, 0x25, 0x26)
	darkText     = walk.RGB(0xe0, 0xe0, 0xe0)
)

// connection is one named, saved server+key pair — connections.json is
// just a JSON array of these.
type connection struct {
	Name          string   `json:"name"`
	VPNAddr       string   `json:"vpn_addr"`
	ClientKey     string   `json:"client_key"`
	GameProcesses []string `json:"game_processes,omitempty"`
}

var (
	exeDir string
	logger *log.Logger

	mu        sync.Mutex
	clientCmd *exec.Cmd

	connections []connection
	// loadedConnectionName is which saved connection (by its name at
	// load time) the fields currently reflect — "" means the fields are
	// a fresh/unsaved entry (after "Новое", or nothing selected yet).
	// Save uses this to update that entry in place even if the Name
	// field itself was just changed, instead of leaving the old name
	// behind as an orphaned duplicate.
	loadedConnectionName string

	mainWin       *walk.MainWindow
	notifyIcon    *walk.NotifyIcon
	statusLabel   *walk.TextLabel
	connList      *walk.ListBox
	nameEdit      *walk.LineEdit
	vpnAddrEdit   *walk.LineEdit
	clientKeyEdit *walk.LineEdit
	gameProcEdit  *walk.LineEdit

	connectAction    *walk.Action
	disconnectAction *walk.Action
	connectBtn       *walk.PushButton
	disconnectBtn    *walk.PushButton
	pingBtn          *walk.PushButton
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
	if iconGray, err = solidIcon(colorIconGray); err != nil {
		return fmt.Errorf("icon: %w", err)
	}
	if iconGreen, err = solidIcon(colorIconGreen); err != nil {
		return fmt.Errorf("icon: %w", err)
	}
	if iconRed, err = solidIcon(colorIconRed); err != nil {
		return fmt.Errorf("icon: %w", err)
	}

	panelBrush := SolidColorBrush{Color: darkPanelBg}

	if err := (MainWindow{
		AssignTo:   &mainWin,
		Title:      "splicertc",
		Size:       Size{Width: 300, Height: 410},
		MinSize:    Size{Width: 280, Height: 390},
		Visible:    false,
		Background: SolidColorBrush{Color: darkWindowBg},
		Layout:     VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 6},
		Children: []Widget{
			ListBox{
				AssignTo: &connList,
				MinSize:  Size{Height: 100},
				// Slightly larger than the rest of the UI — this is the
				// one place users pick a saved server by name, worth
				// making the rows a bit easier to read/click. A classic
				// (non-owner-drawn) ListBox sizes its row height from
				// the font automatically, so bumping PointSize alone is
				// enough — no per-item drawing code needed.
				Font:                  Font{PointSize: 11},
				Background:            panelBrush,
				OnCurrentIndexChanged: onListSelectionChanged,
				OnItemActivated:       onListActivated,
			},
			Composite{
				Background: panelBrush,
				Layout:     Grid{Columns: 2, Spacing: 4},
				Children: []Widget{
					TextLabel{Text: "Название:", TextColor: darkText, Background: panelBrush},
					LineEdit{AssignTo: &nameEdit, TextColor: darkText, Background: panelBrush},

					TextLabel{Text: "Сервер:", ToolTipText: "vpn_addr", TextColor: darkText, Background: panelBrush},
					LineEdit{AssignTo: &vpnAddrEdit, CueBanner: "1.2.3.4:587", TextColor: darkText, Background: panelBrush},

					TextLabel{Text: "Ключ:", ToolTipText: "client_key", TextColor: darkText, Background: panelBrush},
					LineEdit{AssignTo: &clientKeyEdit, PasswordMode: true, TextColor: darkText, Background: panelBrush},

					TextLabel{Text: "Игры:", ToolTipText: "game_processes, через запятую", TextColor: darkText, Background: panelBrush},
					LineEdit{AssignTo: &gameProcEdit, CueBanner: "необязательно", TextColor: darkText, Background: panelBrush},
				},
			},
			Composite{
				Background: SolidColorBrush{Color: darkWindowBg},
				Layout:     HBox{MarginsZero: true, SpacingZero: false},
				Children: []Widget{
					PushButton{Text: "Новое", OnClicked: onNew},
					PushButton{Text: "Сохранить", OnClicked: onSaveConnection},
					PushButton{Text: "Удалить", OnClicked: onDeleteConnection},
				},
			},
			Composite{
				Background: SolidColorBrush{Color: darkWindowBg},
				Layout:     HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{AssignTo: &pingBtn, Text: "Пинг", OnClicked: func() { go onPingCheck() }},
					PushButton{AssignTo: &connectBtn, Text: "Подключиться", OnClicked: onWindowConnect},
					PushButton{AssignTo: &disconnectBtn, Text: "Отключиться", Enabled: false, OnClicked: func() { go disconnect() }},
				},
			},
			TextLabel{AssignTo: &statusLabel, Text: "Статус: отключено", TextColor: darkText, Background: SolidColorBrush{Color: darkWindowBg}},
		},
	}.Create()); err != nil {
		return fmt.Errorf("create window: %w", err)
	}

	applyDarkTheme()

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

	loadConnections()
	refreshConnList()
	if len(connections) == 0 {
		// Nothing saved yet — open the window instead of hiding behind a
		// tray icon nobody knows to click yet.
		mainWin.Show()
	} else {
		selectConnectionByName(connections[0].Name)
	}

	mainWin.Run()
	return nil
}

// applyDarkTheme darkens the title bar (DWM) and asks the classic
// Win32 controls to use their dark visual style (uxtheme's
// "DarkMode_Explorer", available since Windows 10 1809) — both are
// long-standing undocumented-but-widely-used APIs (the same technique
// tools like Windows Terminal/Notepad++ use for non-UWP dark mode).
// Background/TextColor on the widgets themselves (set declaratively
// above) covers what these two calls don't reach — classic controls
// have no single "give me a real dark theme" switch the way modern
// WinUI controls do.
func applyDarkTheme() {
	setDarkTitleBar(mainWin.Handle())
	for _, h := range []win.HWND{
		connList.Handle(), nameEdit.Handle(), vpnAddrEdit.Handle(),
		clientKeyEdit.Handle(), gameProcEdit.Handle(),
		connectBtn.Handle(), disconnectBtn.Handle(), pingBtn.Handle(),
	} {
		setDarkControlTheme(h)
	}
}

func setDarkTitleBar(hwnd win.HWND) {
	dwmapi := syscall.NewLazyDLL("dwmapi.dll")
	proc := dwmapi.NewProc("DwmSetWindowAttribute")
	const dwmwaUseImmersiveDarkMode = 20 // Windows 10 1903+ / 11
	v := int32(1)
	_, _, _ = proc.Call(uintptr(hwnd), dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v))
}

func setDarkControlTheme(hwnd win.HWND) {
	uxtheme := syscall.NewLazyDLL("uxtheme.dll")
	proc := uxtheme.NewProc("SetWindowTheme")
	name, err := syscall.UTF16PtrFromString("DarkMode_Explorer")
	if err != nil {
		return
	}
	_, _, _ = proc.Call(uintptr(hwnd), uintptr(unsafe.Pointer(name)), 0)
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

func configPath() string      { return filepath.Join(exeDir, "client-config.json") }
func connectionsPath() string { return filepath.Join(exeDir, "connections.json") }

// loadConnections reads connections.json. If it doesn't exist yet but
// an already-configured client-config.json does (from before this
// feature existed, or from the single-connection v2 of this app),
// imports it as one named connection instead of just discarding
// whatever was already set up.
func loadConnections() {
	if data, err := os.ReadFile(connectionsPath()); err == nil {
		if err := json.Unmarshal(data, &connections); err != nil {
			logger.Println("connections.json: parse error:", err)
		}
		return
	}

	data, err := os.ReadFile(configPath())
	if err != nil {
		return
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	addr, _ := m["vpn_addr"].(string)
	key, _ := m["client_key"].(string)
	if addr == "" || key == "" {
		return
	}
	c := connection{Name: "По умолчанию", VPNAddr: addr, ClientKey: key}
	if procs, ok := m["game_processes"].([]interface{}); ok {
		for _, p := range procs {
			if s, ok := p.(string); ok {
				c.GameProcesses = append(c.GameProcesses, s)
			}
		}
	}
	connections = []connection{c}
	if err := saveConnections(); err != nil {
		logger.Println("import client-config.json into connections.json:", err)
	}
}

func saveConnections() error {
	out, err := json.MarshalIndent(connections, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(connectionsPath(), out, 0644)
}

func refreshConnList() {
	names := make([]string, len(connections))
	for i, c := range connections {
		names[i] = c.Name
	}
	_ = connList.SetModel(names)
}

func selectConnectionByName(name string) {
	for i, c := range connections {
		if c.Name == name {
			_ = connList.SetCurrentIndex(i)
			return
		}
	}
}

func fillFieldsFrom(c connection) {
	_ = nameEdit.SetText(c.Name)
	_ = vpnAddrEdit.SetText(c.VPNAddr)
	_ = clientKeyEdit.SetText(c.ClientKey)
	_ = gameProcEdit.SetText(strings.Join(c.GameProcesses, ", "))
	loadedConnectionName = c.Name
}

func currentFieldsAsConnection() connection {
	c := connection{
		Name:      strings.TrimSpace(nameEdit.Text()),
		VPNAddr:   strings.TrimSpace(vpnAddrEdit.Text()),
		ClientKey: strings.TrimSpace(clientKeyEdit.Text()),
	}
	procsText := strings.TrimSpace(gameProcEdit.Text())
	if procsText != "" {
		for _, p := range strings.Split(procsText, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.GameProcesses = append(c.GameProcesses, p)
			}
		}
	}
	return c
}

// upsertConnection adds c as a new entry, or replaces an existing one
// in place. originalName (loadedConnectionName at save time) is the
// name the fields were loaded under, if any — matching on that first
// is what makes a rename (Name field changed, then Save) update the
// same entry instead of leaving the old name behind as an orphaned
// duplicate. Falls back to matching by c.Name (the pre-rename
// behavior) so typing a brand new entry's name over an existing one
// still overwrites that one, same as before.
func upsertConnection(c connection, originalName string) {
	if originalName != "" {
		for i := range connections {
			if connections[i].Name == originalName {
				connections[i] = c
				return
			}
		}
	}
	for i := range connections {
		if connections[i].Name == c.Name {
			connections[i] = c
			return
		}
	}
	connections = append(connections, c)
}

func onListSelectionChanged() {
	i := connList.CurrentIndex()
	if i < 0 || i >= len(connections) {
		return
	}
	fillFieldsFrom(connections[i])
}

func onListActivated() {
	i := connList.CurrentIndex()
	if i < 0 || i >= len(connections) {
		return
	}
	c := connections[i]
	fillFieldsFrom(c)
	if err := writeClientConfigFromConnection(c); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось записать конфиг: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	go connect()
}

func onNew() {
	_ = connList.SetCurrentIndex(-1)
	_ = nameEdit.SetText("")
	_ = vpnAddrEdit.SetText("")
	_ = clientKeyEdit.SetText("")
	_ = gameProcEdit.SetText("")
	loadedConnectionName = ""
}

func onSaveConnection() {
	c := currentFieldsAsConnection()
	if c.Name == "" {
		walk.MsgBox(mainWin, "splicertc", "Название подключения не может быть пустым.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	upsertConnection(c, loadedConnectionName)
	if err := saveConnections(); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось сохранить: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	refreshConnList()
	selectConnectionByName(c.Name)
	setStatus("сохранено: " + c.Name)
}

func onDeleteConnection() {
	i := connList.CurrentIndex()
	if i < 0 || i >= len(connections) {
		return
	}
	name := connections[i].Name
	connections = append(connections[:i], connections[i+1:]...)
	if err := saveConnections(); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось сохранить: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	refreshConnList()
	onNew()
	setStatus("удалено: " + name)
}

// writeClientConfigFromConnection compiles a saved connection into
// client-config.json — the file client.exe actually reads. Preserves
// every field this app doesn't expose (insecure, pin_file,
// vpn_tun_name, ...) by reading the existing file as a generic map
// first; seeds the same defaults client-config.example.json ships for
// vpn mode if the file doesn't exist yet.
func writeClientConfigFromConnection(c connection) error {
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

	m["vpn_addr"] = c.VPNAddr
	m["client_key"] = c.ClientKey
	if len(c.GameProcesses) == 0 {
		delete(m, "game_processes")
	} else {
		m["game_processes"] = c.GameProcesses
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), out, 0644)
}

func onWindowConnect() {
	c := currentFieldsAsConnection()
	if c.Name == "" || c.VPNAddr == "" || c.ClientKey == "" {
		walk.MsgBox(mainWin, "splicertc", "Заполни название, адрес сервера и ключ.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	upsertConnection(c, loadedConnectionName)
	if err := saveConnections(); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось сохранить: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	refreshConnList()
	selectConnectionByName(c.Name)
	if err := writeClientConfigFromConnection(c); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось записать конфиг: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	go connect()
}

// onPingCheck does a real, protocol-level reachability check against
// whatever's currently typed in the Server/Key fields — dials the vpn
// channel and runs the actual auth handshake (internal/transport +
// internal/auth, the same packages cmd/client uses), rather than a
// bare ICMP/TCP ping. That's deliberate: a plain port-open check
// wouldn't catch a wrong or not-yet-authorized client_key, and this
// project's own network findings (IDEAS.md §2) show ICMP/port
// reachability alone doesn't reliably predict whether the actual
// tunnel protocol gets through anyway. Doesn't touch server_pin/
// pin_file verification (dials with insecure:true, no pin) — this is a
// "can I reach the server and is this key authorized" check, not a
// substitute for the real pinned connection Connect performs.
func onPingCheck() {
	addr := strings.TrimSpace(vpnAddrEdit.Text())
	keyStr := strings.TrimSpace(clientKeyEdit.Text())
	if addr == "" || keyStr == "" {
		walk.MsgBox(mainWin, "splicertc", "Впиши адрес сервера и ключ.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	seed, err := auth.DecodeKey(keyStr)
	if err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось разобрать ключ: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}

	setStatus("проверка пинга...")

	type pingResult struct {
		ms  int64
		err error
	}
	resCh := make(chan pingResult, 1)
	start := time.Now()
	go func() {
		conn, err := transport.Dial(addr, true, nil)
		if err != nil {
			resCh <- pingResult{err: err}
			return
		}
		defer conn.Close()
		if err := auth.ClientHandshake(conn, seed); err != nil {
			resCh <- pingResult{err: fmt.Errorf("сервер ответил, но ключ не подошёл: %w", err)}
			return
		}
		resCh <- pingResult{ms: time.Since(start).Milliseconds()}
	}()

	select {
	case r := <-resCh:
		if r.err != nil {
			setStatus("пинг не прошёл: " + r.err.Error())
		} else {
			setStatus(fmt.Sprintf("пинг: %d мс, ключ принят", r.ms))
		}
	case <-time.After(6 * time.Second):
		// The dial goroutine above is left running — it'll finish on its
		// own (success or the OS's own TCP timeout) and just write into
		// resCh, which nothing reads after this point; harmless, no
		// explicit cancellation plumbed through for what's meant to be a
		// quick manual check, not a long-running operation.
		setStatus("пинг: сервер не ответил за 6 секунд")
	}
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
// PowerShell window. Uses whatever is currently in client-config.json —
// callers that want a specific saved connection must call
// writeClientConfigFromConnection first (see onWindowConnect/
// onListActivated); the tray menu's plain "Подключиться" intentionally
// just reuses whatever was compiled in last.
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
		// app shouldn't keep claiming to be connected.
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
