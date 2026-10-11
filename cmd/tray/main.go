// Command tray is a small GUI for vpn mode: a list of saved connections
// and a tray icon to connect/disconnect. It just runs client.exe and
// setup-vpn-route.ps1, same as run-vpn.ps1.
//
// Connections are saved in connections.json. Before connecting, the
// selected one is written to client-config.json. client.exe,
// setup-vpn-route.ps1 and wintun.dll must be next to tray.exe.
//
// Files:
//
//	main.go         window, tray menu, global state
//	connections.go  connections.json, the fields, save/delete
//	client.go       starting/stopping client.exe, status
//	ping.go         the "Пинг" button
//	theme.go        dark theme and icons
//	winapi.go       UAC, message box, log file
//
// walk is not thread safe: everything that touches a widget from a
// goroutine has to go through ui().
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"
)

const (
	connectTimeout = 20 * time.Second
	createNoWindow = 0x08000000
)

var (
	exeDir string
	logger *log.Logger

	mu        sync.Mutex
	clientCmd *exec.Cmd
	// set when connect() finished, after that client lines about
	// reconnects change the status
	tunnelUp atomic.Bool

	connections []connection
	// name of the connection shown in the fields ("" = new one),
	// needed so renaming doesn't create a second entry
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
				// bigger font = taller rows
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
					PushButton{AssignTo: &pingBtn, Text: "Пинг", OnClicked: onPingCheck},
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
		// [X] only hides the window, the app stays in the tray
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
	_ = ni.SetToolTip("splicertc - отключено")

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
		// nothing saved yet, show the window
		mainWin.Show()
	} else {
		selectConnectionByName(connections[0].Name)
	}

	mainWin.Run()
	return nil
}

// ui runs f on the GUI thread. Called from the GUI thread itself it
// still works (f is queued and runs right after the current handler).
func ui(f func()) {
	if mainWin == nil {
		f() // before the window exists, and in tests
		return
	}
	mainWin.Synchronize(f)
}
