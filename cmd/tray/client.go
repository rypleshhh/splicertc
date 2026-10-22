package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
)

// Everything here is called from goroutines, so widget access goes
// through ui().

func setStatus(text string) {
	logger.Println("status:", text)
	ui(func() {
		if statusLabel != nil {
			_ = statusLabel.SetText("Статус: " + text)
		}
		if notifyIcon != nil {
			_ = notifyIcon.SetToolTip("splicertc - " + text)
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

func setConnected(connected bool) {
	ui(func() {
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
	})
}

func fail(text string) {
	tunnelUp.Store(false)
	logger.Println("error:", text)
	setStatus(text)
	setIcon(iconRed)
	setConnected(false)
}

// connect starts client.exe, waits until it's connected and runs the
// routing script. It uses whatever is in client-config.json now.
func connect() {
	// a second click must not start a second client.exe with its own TUN
	tunnelUp.Store(false)
	stopClient()
	lastClientErr.Store(int32(errNone))

	setConnected(false)
	setStatus("подключение...")
	setIcon(iconGray)

	clientExe := filepath.Join(exeDir, "client.exe")
	cfgPath := configPath()
	scriptPath := filepath.Join(exeDir, "setup-vpn-route.ps1")
	for _, p := range []string{clientExe, cfgPath, scriptPath} {
		if _, err := os.Stat(p); err != nil {
			fail(filepath.Base(p) + " не найден рядом с tray.exe")
			return
		}
	}
	serverIP, err := serverIPFromConfig(cfgPath)
	if err != nil {
		fail("адрес сервера: " + err.Error())
		return
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

	select {
	case ok := <-connectedCh:
		if !ok {
			return
		}
	case <-time.After(connectTimeout):
		fail("клиент не подключился за " + connectTimeout.String() + ", смотри tray.log")
		stopClient()
		return
	}

	setStatus("настройка маршрутов...")
	rc := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-ServerIP", serverIP)
	rc.Dir = exeDir
	rc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := rc.CombinedOutput()
	logger.Println("setup-vpn-route.ps1 output:\n" + string(out))
	if err != nil {
		fail("не удалось настроить маршрутизацию, смотри tray.log")
		stopClient()
		teardownRoutes()
		return
	}

	setStatus("подключено")
	setIcon(iconGreen)
	setConnected(true)
	tunnelUp.Store(true)
}

// serverIPFromConfig returns the IPv4 address of vpn_addr. The routing
// script needs it for the route that keeps the tunnel's own connection
// on the real gateway.
func serverIPFromConfig(cfgPath string) (string, error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", err
	}
	var cfg struct {
		VPNAddr string `json:"vpn_addr"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(cfg.VPNAddr)
	if err != nil {
		return "", fmt.Errorf("vpn_addr %q: %w", cfg.VPNAddr, err)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return "", fmt.Errorf("%s has no IPv4 address", host)
}

// onClientLine updates the status when client.exe loses the connection
// and gets it back (it reconnects by itself, the routes stay).
func onClientLine(line []byte) {
	if !tunnelUp.Load() {
		return
	}
	switch {
	case strings.Contains(string(line), "vpn: connection lost"):
		setStatus("переподключение...")
		setIcon(iconGray)
	case containsConnected(line):
		setStatus("подключено")
		setIcon(iconGreen)
	}
}

// scanForConnected writes client output to the log and sends true when
// it sees "connected to vpn channel", or false if the output ends first.
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
					noteClientLine(line)
					if !seen && containsConnected(line) {
						seen = true
						select {
						case connectedCh <- true:
						default:
						}
					} else if seen {
						onClientLine(line)
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
	tunnelUp.Store(false)
	setStatus("отключение...")
	stopClient()
	teardownRoutes()
	setStatus("отключено")
	setIcon(iconGray)
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
	// Windows removes the TUN adapter and its routes when the process dies.
	// No Wait() here, the goroutine in connect() already waits on it.
	_ = c.Process.Kill()
}
