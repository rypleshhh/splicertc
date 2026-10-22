package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/transport"
)

const pingTimeout = 6 * time.Second

// onPingCheck measures the plain TCP connect (one round trip) and then
// the full TLS + auth handshake with the key from the fields, so it
// shows both the latency and that the key is accepted. The certificate
// is checked the way client.exe would check it. Runs on the GUI thread,
// the network part runs in a goroutine.
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
	dc, unverified := pingDialConfig()

	setStatus("проверка пинга...")
	go func() {
		resCh := make(chan string, 1)
		go func() { resCh <- ping(addr, dc, seed, unverified) }()
		select {
		case r := <-resCh:
			setStatus(r)
		case <-time.After(pingTimeout):
			// the goroutine above will finish by itself (deadlines)
			setStatus(fmt.Sprintf("пинг: сервер не ответил за %d секунд", int(pingTimeout.Seconds())))
		}
	}()
}

// ping returns the status line for one check.
func ping(addr string, dc transport.DialConfig, seed []byte, unverified string) string {
	start := time.Now()
	raw, err := net.DialTimeout("tcp", addr, pingTimeout)
	if err != nil {
		return "пинг не прошёл: " + err.Error()
	}
	tcpTime := time.Since(start)
	raw.Close()

	start = time.Now()
	conn, err := transport.Dial(addr, dc)
	if err != nil {
		return fmt.Sprintf("TCP %d мс, но TLS не прошёл: %v", tcpTime.Milliseconds(), err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(pingTimeout))
	if err := auth.ClientHandshake(conn, seed); err != nil {
		return fmt.Sprintf("TCP %d мс, сервер ответил, но ключ не подошёл: %v", tcpTime.Milliseconds(), err)
	}
	s := fmt.Sprintf("TCP %d мс, вход %d мс, ключ принят", tcpTime.Milliseconds(), time.Since(start).Milliseconds())
	if unverified != "" {
		s += ", " + unverified
	}
	return s
}

// clientTLSConfig is the part of client-config.json about checking the
// server certificate.
type clientTLSConfig struct {
	ServerPin  string `json:"server_pin"`
	PinFile    string `json:"pin_file"`
	ServerName string `json:"server_name"`
	Insecure   bool   `json:"insecure"`
}

func readClientTLSConfig() clientTLSConfig {
	var cfg clientTLSConfig
	if data, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	if cfg.PinFile != "" && !filepath.IsAbs(cfg.PinFile) {
		cfg.PinFile = filepath.Join(exeDir, cfg.PinFile) // client.exe runs with exeDir as its directory
	}
	return cfg
}

// pinConfig returns server_pin and the full path of pin_file from
// client-config.json (either can be empty).
func pinConfig() (serverPin, pinPath string) {
	cfg := readClientTLSConfig()
	return cfg.ServerPin, cfg.PinFile
}

// pingDialConfig checks the certificate like client.exe: against the
// saved pin; without one, against server_name with the normal CA check,
// unless the client would accept anything anyway (pin_file not created
// yet, or insecure). Then unverified says so.
func pingDialConfig() (dc transport.DialConfig, unverified string) {
	cfg := readClientTLSConfig()
	dc.ServerName = cfg.ServerName
	hexPin := cfg.ServerPin
	if hexPin == "" && cfg.PinFile != "" {
		if raw, err := os.ReadFile(cfg.PinFile); err == nil {
			hexPin = string(raw)
		}
	}
	if pin, err := transport.ParsePin(hexPin); err == nil {
		dc.Pin = pin
		return dc, ""
	}
	switch {
	case cfg.PinFile != "":
		dc.Insecure = true
		return dc, "сертификат не проверен (пина ещё нет)"
	case cfg.Insecure:
		dc.Insecure = true
		return dc, "сертификат не проверен (insecure)"
	}
	return dc, ""
}
