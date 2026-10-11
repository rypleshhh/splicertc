package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/transport"
)

// onPingCheck connects to the server and does the auth handshake with
// the key from the fields, so it checks that the key is accepted, not
// just that the port is open. Runs on the GUI thread, the network part
// runs in a goroutine.
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
	pin := savedPin()

	setStatus("проверка пинга...")
	go func() {
		type pingResult struct {
			ms  int64
			err error
		}
		resCh := make(chan pingResult, 1)
		start := time.Now()
		go func() {
			// with a saved pin the server cert is checked like client.exe
			// does; without one (first connect) any cert is accepted
			conn, err := transport.Dial(addr, true, pin)
			if err != nil {
				resCh <- pingResult{err: err}
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
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
			// the goroutine above will finish by itself (deadline)
			setStatus("пинг: сервер не ответил за 6 секунд")
		}
	}()
}

// savedPin returns the server cert fingerprint client.exe would check:
// server_pin from client-config.json, or the contents of its pin_file.
// nil if there's none yet.
func savedPin() []byte {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil
	}
	var cfg struct {
		ServerPin string `json:"server_pin"`
		PinFile   string `json:"pin_file"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return nil
	}
	hexPin := cfg.ServerPin
	if hexPin == "" && cfg.PinFile != "" {
		path := cfg.PinFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(exeDir, path) // client.exe runs with exeDir as its directory
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		hexPin = strings.TrimSpace(string(raw))
	}
	pin, err := hex.DecodeString(hexPin)
	if err != nil || len(pin) == 0 {
		return nil
	}
	return pin
}
