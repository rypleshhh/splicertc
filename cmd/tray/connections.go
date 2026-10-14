package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/lxn/walk"
)

// connection is one entry in connections.json.
type connection struct {
	Name          string   `json:"name"`
	VPNAddr       string   `json:"vpn_addr"`
	ClientKey     string   `json:"client_key"`
	GameProcesses []string `json:"game_processes,omitempty"`
}

// Files with private keys: readable only by the owner (on Windows the
// folder ACL matters more, but there's no reason to ask for more).
const secretFileMode = 0600

func configPath() string      { return filepath.Join(exeDir, "client-config.json") }
func connectionsPath() string { return filepath.Join(exeDir, "connections.json") }

// loadConnections reads connections.json. If there's none but
// client-config.json exists, it is imported as one connection.
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
	return os.WriteFile(connectionsPath(), out, secretFileMode)
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

// upsertConnection updates the entry called originalName (for renames),
// or the one with the same name, or adds a new one.
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

// writeClientConfigFromConnection writes the connection into
// client-config.json. Other fields in the file are kept as they are.
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
	return os.WriteFile(configPath(), out, secretFileMode)
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
