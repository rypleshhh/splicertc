package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"

	"tcp-dormtun/internal/auth"
)

// connection is one saved connection.
type connection struct {
	Name          string
	VPNAddr       string
	ClientKey     string
	GameProcesses []string
	// DPAPI blob that could not be decrypted (another user or machine);
	// kept as is so a save doesn't destroy it
	sealedKey string
}

// storedConnection is one entry in connections.json. The key is kept
// only encrypted (see dpapi.go).
type storedConnection struct {
	Name           string `json:"name"`
	VPNAddr        string `json:"vpn_addr"`
	ClientKeyDPAPI string `json:"client_key_dpapi,omitempty"`
	// plain text key written by older versions, read once and replaced
	// by client_key_dpapi on load
	ClientKey     string   `json:"client_key,omitempty"`
	GameProcesses []string `json:"game_processes,omitempty"`
}

func configPath() string      { return filepath.Join(exeDir, "client-config.json") }
func connectionsPath() string { return filepath.Join(exeDir, "connections.json") }

// decodeConnections parses connections.json. migrate is true when there
// were plain text keys, the file should then be saved again. undecryptable
// lists entries whose key can't be decrypted by this user.
func decodeConnections(data []byte) (cs []connection, migrate bool, undecryptable []string, err error) {
	var stored []storedConnection
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, false, nil, err
	}
	for _, s := range stored {
		c := connection{Name: s.Name, VPNAddr: s.VPNAddr, GameProcesses: s.GameProcesses}
		if s.ClientKey != "" {
			migrate = true
		}
		if s.ClientKeyDPAPI != "" {
			key, err := unprotectString(s.ClientKeyDPAPI)
			switch {
			case err == nil:
				c.ClientKey = key
			case s.ClientKey != "":
				c.ClientKey = s.ClientKey
			default:
				logger.Printf("connections.json: %q: decrypt key: %v", s.Name, err)
				c.sealedKey = s.ClientKeyDPAPI
				undecryptable = append(undecryptable, s.Name)
			}
		} else {
			c.ClientKey = s.ClientKey
		}
		cs = append(cs, c)
	}
	return cs, migrate, undecryptable, nil
}

func encodeConnections(cs []connection) ([]byte, error) {
	stored := make([]storedConnection, len(cs))
	for i, c := range cs {
		s := storedConnection{Name: c.Name, VPNAddr: c.VPNAddr, GameProcesses: c.GameProcesses, ClientKeyDPAPI: c.sealedKey}
		if c.ClientKey != "" {
			sealed, err := protectString(c.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("encrypt key of %q: %w", c.Name, err)
			}
			s.ClientKeyDPAPI = sealed
		}
		stored[i] = s
	}
	return json.MarshalIndent(stored, "", "  ")
}

// loadConnections reads connections.json. If there's none but
// client-config.json has a key, it is imported as one connection.
// Runs on the GUI thread (shows message boxes).
func loadConnections() {
	data, err := os.ReadFile(connectionsPath())
	if err != nil {
		importFromClientConfig()
		return
	}
	cs, migrate, undecryptable, err := decodeConnections(data)
	if err != nil {
		// keep the broken file: saving the empty list over it would wipe all keys
		logger.Println("connections.json: parse error:", err)
		moved, mvErr := moveAside(connectionsPath(), time.Now())
		if mvErr != nil {
			logger.Println("connections.json: move aside:", mvErr)
			walk.MsgBox(mainWin, "splicertc", "connections.json повреждён ("+err.Error()+
				") и его не удалось переименовать: "+mvErr.Error()+
				"\n\nПочини или убери файл вручную, иначе сохранение подключений его перезапишет.",
				walk.MsgBoxOK|walk.MsgBoxIconError)
			return
		}
		walk.MsgBox(mainWin, "splicertc", "connections.json повреждён: "+err.Error()+
			"\n\nФайл переименован в "+filepath.Base(moved)+", ключи из него можно достать вручную. "+
			"Список подключений начат заново.",
			walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	connections = cs
	if migrate {
		if err := saveConnections(); err != nil {
			logger.Println("connections.json: encrypt plain text keys:", err)
		} else {
			logger.Println("connections.json: plain text keys encrypted")
		}
	}
	if len(undecryptable) > 0 {
		walk.MsgBox(mainWin, "splicertc", "Не удалось расшифровать ключ подключений: "+strings.Join(undecryptable, ", ")+
			".\n\nКлючи шифруются для пользователя Windows, файл мог прийти от другого пользователя или компьютера. "+
			"Впиши ключ заново.",
			walk.MsgBoxOK|walk.MsgBoxIconWarning)
	}
}

// moveAside renames path to path.broken-<time> and returns the new name.
func moveAside(path string, now time.Time) (string, error) {
	moved := path + ".broken-" + now.Format("20060102-150405")
	return moved, os.Rename(path, moved)
}

// importFromClientConfig turns client_key from an old client-config.json
// into a saved connection, and takes the key out of client-config.json.
func importFromClientConfig() {
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
		return
	}
	if err := writeClientConfigFromConnection(c); err != nil {
		logger.Println("remove client_key from client-config.json:", err)
	}
}

func saveConnections() error {
	out, err := encodeConnections(connections)
	if err != nil {
		return err
	}
	return writeFileAtomic(connectionsPath(), out)
}

// writeFileAtomic writes a temp file in the same folder and renames it
// over path, so a crash or a full disk never leaves a half-written file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
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
	replace := func(i int) {
		if c.ClientKey == "" {
			// the key field is empty because the key couldn't be decrypted
			c.sealedKey = connections[i].sealedKey
		}
		connections[i] = c
	}
	if originalName != "" {
		for i := range connections {
			if connections[i].Name == originalName {
				replace(i)
				return
			}
		}
	}
	for i := range connections {
		if connections[i].Name == c.Name {
			replace(i)
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
	if c.ClientKey == "" {
		walk.MsgBox(mainWin, "splicertc", "У подключения нет ключа, впиши его.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	startConnect(c)
}

func onNew() {
	_ = connList.SetCurrentIndex(-1)
	_ = nameEdit.SetText("")
	_ = vpnAddrEdit.SetText("")
	_ = clientKeyEdit.SetText("")
	_ = gameProcEdit.SetText("")
	loadedConnectionName = ""
}

// saveFields saves the fields as a connection. false if it didn't work
// (the user has already been told why).
func saveFields() bool {
	c := currentFieldsAsConnection()
	if c.Name == "" {
		walk.MsgBox(mainWin, "splicertc", "Название подключения не может быть пустым.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return false
	}
	upsertConnection(c, loadedConnectionName)
	if err := saveConnections(); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось сохранить: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return false
	}
	refreshConnList()
	selectConnectionByName(c.Name)
	return true
}

func onSaveConnection() {
	if saveFields() {
		setStatus("сохранено: " + strings.TrimSpace(nameEdit.Text()))
	}
}

func onDeleteConnection() {
	i := connList.CurrentIndex()
	if i < 0 || i >= len(connections) {
		return
	}
	name := connections[i].Name
	if walk.MsgBox(mainWin, "splicertc", "Удалить подключение «"+name+"» вместе с его ключом?",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	connections = append(connections[:i], connections[i+1:]...)
	if err := saveConnections(); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось сохранить: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	refreshConnList()
	onNew()
	setStatus("удалено: " + name)
}

// authorizedKeyLine is the entry for the server's authorized_keys.json.
func authorizedKeyLine(name string, pub []byte) string {
	n, _ := json.Marshal(name) // a string always marshals
	return fmt.Sprintf(`{ "name": %s, "public_key": "%s" }`, n, auth.EncodeKey(pub))
}

// onNewKey makes a key pair for the connection in the fields. The private
// key goes into the key field and is saved; only the public key line is
// put on the clipboard for the server admin.
func onNewKey() {
	name := strings.TrimSpace(nameEdit.Text())
	if name == "" {
		walk.MsgBox(mainWin, "splicertc", "Сначала впиши название подключения: оно попадёт в authorized_keys.json на сервере.",
			walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	if strings.TrimSpace(clientKeyEdit.Text()) != "" &&
		walk.MsgBox(mainWin, "splicertc", "У подключения уже есть ключ. Заменить его новым? Старый ключ будет потерян.",
			walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdYes {
		return
	}
	pub, seed, err := auth.GenerateKeypair()
	if err != nil {
		walk.MsgBox(mainWin, "splicertc", "Не удалось создать ключ: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	_ = clientKeyEdit.SetText(auth.EncodeKey(seed))
	if !saveFields() {
		return
	}
	if err := walk.Clipboard().SetText(authorizedKeyLine(name, pub)); err != nil {
		walk.MsgBox(mainWin, "splicertc", "Ключ сохранён, но скопировать строку не удалось: "+err.Error(),
			walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	setStatus("новый ключ сохранён. Строка для authorized_keys.json скопирована: отправь её админу сервера " +
		"(это открытый ключ, секретный остаётся здесь)")
}

// clientConfigJSON returns client-config.json (existing, may be nil) with
// the connection's fields. The key is never written there: client.exe
// gets it from the environment, and a key left from older versions is
// removed. Other fields are kept as they are.
func clientConfigJSON(existing []byte, c connection) ([]byte, error) {
	m := map[string]interface{}{}
	if len(existing) > 0 {
		// a broken file is not replaced: it can hold server_pin and the like
		if err := json.Unmarshal(existing, &m); err != nil {
			return nil, fmt.Errorf("client-config.json повреждён: %w", err)
		}
	}
	if len(m) == 0 {
		m = map[string]interface{}{
			"mode":        "vpn",
			"vpn_tun_mtu": 1400,
			"pin_file":    "known_server.pin",
		}
	}

	m["vpn_addr"] = c.VPNAddr
	delete(m, "client_key")
	if len(c.GameProcesses) == 0 {
		delete(m, "game_processes")
	} else {
		m["game_processes"] = c.GameProcesses
	}
	return json.MarshalIndent(m, "", "  ")
}

func writeClientConfigFromConnection(c connection) error {
	existing, err := os.ReadFile(configPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	out, err := clientConfigJSON(existing, c)
	if err != nil {
		return err
	}
	return writeFileAtomic(configPath(), out)
}

func onWindowConnect() {
	c := currentFieldsAsConnection()
	if c.Name == "" || c.VPNAddr == "" || c.ClientKey == "" {
		mainWin.Show()
		walk.MsgBox(mainWin, "splicertc", "Заполни название, адрес сервера и ключ.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	if !saveFields() {
		return
	}
	startConnect(c)
}
