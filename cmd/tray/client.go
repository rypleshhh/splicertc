package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lxn/walk"
)

// client.exe reads its key from this variable before the config, so the
// key never has to be written to client-config.json.
const clientKeyEnv = "SPLICERTC_CLIENT_KEY"

// connectMu is held while a connect is in progress. The button, the tray
// menu and double-click all start one, a second click must not start a
// second client.exe with its own TUN.
var connectMu sync.Mutex

// Everything below is called from goroutines, so widget access goes
// through ui().

func setStatus(text string) {
	logger.Println("status:", text)
	ui(func() {
		if statusLabel != nil {
			_ = statusLabel.SetText("Статус: " + text)
		}
		if notifyIcon != nil {
			// the tooltip is limited to 128 characters
			tip := []rune("splicertc - " + text)
			if len(tip) > 127 {
				tip = tip[:127]
			}
			_ = notifyIcon.SetToolTip(string(tip))
		}
	})
}

func setIcon(icon *walk.Icon) {
	ui(func() {
		if notifyIcon != nil && icon != nil {
			_ = notifyIcon.SetIcon(icon)
		}
	})
}

// setActive switches the buttons between "can connect" and "connecting
// or connected" (then only disconnect is enabled, it also cancels a
// connect in progress).
func setActive(active bool) {
	ui(func() {
		if connectAction != nil {
			_ = connectAction.SetEnabled(!active)
		}
		if disconnectAction != nil {
			_ = disconnectAction.SetEnabled(active)
		}
		if connectBtn != nil {
			connectBtn.SetEnabled(!active)
		}
		if disconnectBtn != nil {
			disconnectBtn.SetEnabled(active)
		}
	})
}

func fail(text string) {
	tunnelUp.Store(false)
	logger.Println("error:", text)
	setStatus(text)
	setIcon(iconRed)
	setActive(false)
}

// startConnect writes c to client-config.json and connects in the
// background. Called on the GUI thread; a click while a connect is
// still running is ignored.
func startConnect(c connection) {
	if !connectMu.TryLock() {
		setStatus("уже подключаюсь...")
		return
	}
	if err := writeClientConfigFromConnection(c); err != nil {
		connectMu.Unlock()
		walk.MsgBox(mainWin, "splicertc", "Не удалось записать конфиг: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	go func() {
		defer connectMu.Unlock()
		connect(c.ClientKey)
	}()
}

// connect starts client.exe with the key, waits until it's connected and
// runs the route script. Only called by startConnect.
func connect(key string) {
	tunnelUp.Store(false)
	stopClient()
	lastClientErr.Store(int32(errNone))
	// disconnect() bumps connGen; then this connect must stop and not
	// report anything
	gen := connGen.Load()
	cancelled := func() bool { return connGen.Load() != gen }

	setActive(true)
	setStatus("подключение...")
	setIcon(iconGray)

	clientExe := filepath.Join(exeDir, "client.exe")
	cfgPath := configPath()
	for _, p := range []string{clientExe, cfgPath} {
		if _, err := os.Stat(p); err != nil {
			fail(filepath.Base(p) + " не найден рядом с tray.exe")
			return
		}
	}
	tc, err := loadTunConfig()
	if err != nil {
		fail("client-config.json: " + err.Error())
		return
	}

	c := exec.Command(clientExe, "-config", cfgPath)
	c.Dir = exeDir
	c.Env = append(os.Environ(), clientKeyEnv+"="+key)
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
	if err := addToClientJob(c.Process.Pid); err != nil {
		// not fatal: only matters if the tray itself dies
		logger.Println("client.exe: add to job object:", err)
	}

	mu.Lock()
	if cancelled() {
		mu.Unlock()
		_ = c.Process.Kill()
		_ = c.Wait()
		return
	}
	clientCmd = c
	mu.Unlock()

	connectedCh := make(chan string, 1)
	go scanForConnected(stdout, connectedCh)
	go scanForConnected(stderr, connectedCh)
	go func() {
		// client.exe can exit later (connection lost etc.)
		err := c.Wait()
		mu.Lock()
		stillOurs := clientCmd == c
		if stillOurs {
			clientCmd = nil
		}
		mu.Unlock()
		if stillOurs {
			logger.Println("client.exe exited:", err)
			teardownRoutes()
			reportClientExit()
		}
	}()

	var line string
	select {
	case line = <-connectedCh:
		if line == "" {
			return // exited before connecting, the Wait goroutine reports it
		}
	case <-time.After(connectTimeout):
		if !cancelled() {
			fail("клиент не подключился за " + connectTimeout.String() + ", смотри tray.log")
			stopClient()
		}
		return
	}
	if cancelled() {
		return
	}

	serverIP, err := serverIPFromLine(line)
	if err != nil {
		fail("IP сервера из лога клиента: " + err.Error())
		stopClient()
		return
	}
	args, err := setupArgs(serverIP, tc)
	if err != nil {
		fail("параметры маршрутов: " + err.Error())
		stopClient()
		return
	}

	setStatus("настройка маршрутов...")
	out, err := runRouteScript(args)
	logger.Println("route script output:\n" + string(out))
	if cancelled() {
		// disconnect() ran while the script was working and may have
		// removed the IPv6 block before the script added it
		teardownRoutes()
		return
	}
	if err != nil {
		fail("не удалось настроить маршрутизацию, смотри tray.log")
		stopClient()
		teardownRoutes()
		return
	}

	setStatus("подключено")
	setIcon(iconGreen)
	tunnelUp.Store(true)
}

// onClientLine updates the status when client.exe loses the connection
// and gets it back (it reconnects by itself, the routes stay).
func onClientLine(line string) {
	if !tunnelUp.Load() {
		return
	}
	switch {
	case strings.Contains(line, "vpn: connection lost"):
		setStatus("переподключение...")
		setIcon(iconGray)
	case strings.Contains(line, connectedMarker):
		setStatus("подключено")
		setIcon(iconGreen)
	}
}

// scanForConnected writes client output to the log and sends the first
// "connected to vpn channel" line, or "" if the output ends first.
func scanForConnected(r io.Reader, connectedCh chan<- string) {
	buf := make([]byte, 4096)
	var line []byte
	seen := false
	for {
		n, err := r.Read(buf)
		if n > 0 {
			for _, b := range buf[:n] {
				if b != '\n' {
					line = append(line, b)
					continue
				}
				s := strings.TrimRight(string(line), "\r")
				line = line[:0]
				logger.Println("client:", s)
				noteClientLine(s)
				if !seen && strings.Contains(s, connectedMarker) {
					seen = true
					select {
					case connectedCh <- s:
					default:
					}
				} else if seen {
					onClientLine(s)
				}
			}
		}
		if err != nil {
			if len(line) > 0 {
				logger.Println("client:", string(line))
			}
			if !seen {
				select {
				case connectedCh <- "":
				default:
				}
			}
			return
		}
	}
}

func disconnect() {
	connGen.Add(1)
	tunnelUp.Store(false)
	setStatus("отключение...")
	stopClient()
	teardownRoutes()
	setStatus("отключено")
	setIcon(iconGray)
	setActive(false)
}

func stopClient() {
	mu.Lock()
	c := clientCmd
	clientCmd = nil
	mu.Unlock()
	if c == nil || c.Process == nil {
		return
	}
	// Windows removes the TUN adapter and its routes when the process dies.
	// No Wait() here, the goroutine in connect() already waits on it.
	_ = c.Process.Kill()
}
