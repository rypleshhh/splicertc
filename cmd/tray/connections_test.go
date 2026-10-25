package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tcp-dormtun/internal/auth"
)

func TestDPAPIRoundTrip(t *testing.T) {
	const key = "c2VjcmV0LXNlZWQtMzItYnl0ZXMtbG9uZy0xMjM0NTY="
	sealed, err := protectString(key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, key) {
		t.Fatal("the sealed value contains the key")
	}
	got, err := unprotectString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got != key {
		t.Errorf("got %q, want %q", got, key)
	}
}

// Keys are written only encrypted, never as client_key.
func TestEncodeConnectionsWritesNoPlainKey(t *testing.T) {
	const key = "plain-key-value"
	out, err := encodeConnections([]connection{{Name: "a", VPNAddr: "1.1.1.1:587", ClientKey: key}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), key) || strings.Contains(string(out), `"client_key"`) {
		t.Fatalf("plain key in connections.json: %s", out)
	}
	cs, migrate, undecryptable, err := decodeConnections(out)
	if err != nil {
		t.Fatal(err)
	}
	if migrate || len(undecryptable) != 0 {
		t.Errorf("migrate=%v undecryptable=%v, want neither", migrate, undecryptable)
	}
	if len(cs) != 1 || cs[0].ClientKey != key || cs[0].VPNAddr != "1.1.1.1:587" {
		t.Errorf("got %+v", cs)
	}
}

func TestDecodeConnections(t *testing.T) {
	sealed, err := protectString("sealed-key")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		json          string
		wantKey       string
		wantSealed    string
		wantMigrate   bool
		wantUndecrypt bool
	}{
		{name: "old plain text key is migrated",
			json: `[{"name":"a","vpn_addr":"x:1","client_key":"plain"}]`, wantKey: "plain", wantMigrate: true},
		{name: "encrypted key",
			json: `[{"name":"a","vpn_addr":"x:1","client_key_dpapi":"` + sealed + `"}]`, wantKey: "sealed-key"},
		{name: "both: the plain copy is dropped",
			json:    `[{"name":"a","vpn_addr":"x:1","client_key":"plain","client_key_dpapi":"` + sealed + `"}]`,
			wantKey: "sealed-key", wantMigrate: true},
		{name: "undecryptable blob is kept",
			json:       `[{"name":"a","vpn_addr":"x:1","client_key_dpapi":"AAAA"}]`,
			wantSealed: "AAAA", wantUndecrypt: true},
		{name: "no key", json: `[{"name":"a","vpn_addr":"x:1"}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cs, migrate, undecryptable, err := decodeConnections([]byte(c.json))
			if err != nil {
				t.Fatal(err)
			}
			if len(cs) != 1 {
				t.Fatalf("got %d entries", len(cs))
			}
			if cs[0].ClientKey != c.wantKey || cs[0].sealedKey != c.wantSealed {
				t.Errorf("key %q sealed %q, want %q and %q", cs[0].ClientKey, cs[0].sealedKey, c.wantKey, c.wantSealed)
			}
			if migrate != c.wantMigrate {
				t.Errorf("migrate = %v, want %v", migrate, c.wantMigrate)
			}
			if (len(undecryptable) > 0) != c.wantUndecrypt {
				t.Errorf("undecryptable = %v", undecryptable)
			}
		})
	}
}

// A blob that can't be decrypted survives a save, also when the entry
// is saved again from the fields (where the key field is empty).
func TestUndecryptableKeySurvivesSave(t *testing.T) {
	connections = []connection{{Name: "a", VPNAddr: "1.1.1.1:587", sealedKey: "AAAA"}}
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "a", VPNAddr: "2.2.2.2:587"}, "a")
	out, err := encodeConnections(connections)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"client_key_dpapi": "AAAA"`) {
		t.Errorf("sealed key lost: %s", out)
	}
}

func TestDecodeConnectionsBrokenJSON(t *testing.T) {
	if _, _, _, err := decodeConnections([]byte(`[{"name":`)); err == nil {
		t.Fatal("expected a parse error")
	}
}

func TestMoveAside(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connections.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	moved, err := moveAside(path, time.Date(2026, 10, 22, 15, 4, 5, 0, time.Local))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(moved) != "connections.json.broken-20261022-150405" {
		t.Errorf("moved to %s", moved)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the original file is still there")
	}
	if data, _ := os.ReadFile(moved); string(data) != "{broken" {
		t.Errorf("contents changed: %q", data)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client-config.json")
	for _, content := range []string{"first", "second"} {
		if err := writeFileAtomic(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		if data, _ := os.ReadFile(path); string(data) != content {
			t.Errorf("got %q, want %q", data, content)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left: %v", entries)
	}
}

func TestClientConfigJSON(t *testing.T) {
	c := connection{Name: "a", VPNAddr: "203.0.113.5:587", ClientKey: "secret", GameProcesses: []string{"game.exe"}}
	cases := []struct {
		name     string
		existing string
		wantErr  bool
		check    func(t *testing.T, m map[string]interface{})
	}{
		{name: "new file gets defaults", existing: "", check: func(t *testing.T, m map[string]interface{}) {
			if m["mode"] != "vpn" || m["pin_file"] != "known_server.pin" {
				t.Errorf("defaults missing: %v", m)
			}
		}},
		{name: "old client_key is removed, other fields kept",
			existing: `{"mode":"vpn","client_key":"old","server_pin":"ab","vpn_subnet":"10.70.0.0/24"}`,
			check: func(t *testing.T, m map[string]interface{}) {
				if _, ok := m["client_key"]; ok {
					t.Error("client_key still there")
				}
				if m["server_pin"] != "ab" || m["vpn_subnet"] != "10.70.0.0/24" {
					t.Errorf("other fields lost: %v", m)
				}
			}},
		{name: "broken file is not overwritten", existing: `{"server_pin":`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := clientConfigJSON([]byte(tc.existing), c)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %s", out)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), "secret") {
				t.Fatalf("key written to client-config.json: %s", out)
			}
			var m map[string]interface{}
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatal(err)
			}
			if m["vpn_addr"] != c.VPNAddr {
				t.Errorf("vpn_addr = %v", m["vpn_addr"])
			}
			tc.check(t, m)
		})
	}
}

func TestAuthorizedKeyLine(t *testing.T) {
	pub, _, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	line := authorizedKeyLine(`Вася "ноут"`, pub)
	var e auth.AuthorizedEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	if e.Name != `Вася "ноут"` || e.PublicKey != auth.EncodeKey(pub) {
		t.Errorf("got %+v", e)
	}
}

// A second connect while one is running is ignored and doesn't touch
// client-config.json.
func TestStartConnectIgnoredWhileConnecting(t *testing.T) {
	old := exeDir
	exeDir = t.TempDir()
	defer func() { exeDir = old }()

	connectMu.Lock()
	defer connectMu.Unlock()
	startConnect(connection{Name: "a", VPNAddr: "1.1.1.1:587", ClientKey: "k"})
	if _, err := os.Stat(configPath()); !os.IsNotExist(err) {
		t.Error("client-config.json was written by an ignored connect")
	}
}

func TestUpsertConnectionAddsNew(t *testing.T) {
	connections = nil
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "a", VPNAddr: "1.1.1.1:587"}, "")
	if len(connections) != 1 || connections[0].VPNAddr != "1.1.1.1:587" {
		t.Fatalf("expected one connection with the given address, got %+v", connections)
	}
}

func TestUpsertConnectionUpdatesExistingByName(t *testing.T) {
	connections = []connection{{Name: "a", VPNAddr: "1.1.1.1:587"}}
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "a", VPNAddr: "2.2.2.2:587"}, "a")
	if len(connections) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(connections))
	}
	if connections[0].VPNAddr != "2.2.2.2:587" {
		t.Errorf("expected the address to be updated to 2.2.2.2:587, got %q", connections[0].VPNAddr)
	}
}

func TestUpsertConnectionKeepsDistinctNamesSeparate(t *testing.T) {
	connections = []connection{{Name: "a", VPNAddr: "1.1.1.1:587"}}
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "b", VPNAddr: "2.2.2.2:587"}, "")
	if len(connections) != 2 {
		t.Fatalf("expected two distinct connections, got %d", len(connections))
	}
}

// Renaming an entry should not leave the old one in the list.
func TestUpsertConnectionRenamesInPlace(t *testing.T) {
	connections = []connection{
		{Name: "По умолчанию", VPNAddr: "1.1.1.1:587", ClientKey: "key-a"},
	}
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "Мой сервер", VPNAddr: "1.1.1.1:587", ClientKey: "key-a"}, "По умолчанию")

	if len(connections) != 1 {
		t.Fatalf("expected the rename to replace the one existing entry, got %d entries: %+v", len(connections), connections)
	}
	if connections[0].Name != "Мой сервер" {
		t.Errorf("expected the entry's name to be updated to %q, got %q", "Мой сервер", connections[0].Name)
	}
}

// Renaming A to an existing name B only changes A's slot.
func TestUpsertConnectionRenameOntoAnotherExistingNameMerges(t *testing.T) {
	connections = []connection{
		{Name: "A", VPNAddr: "1.1.1.1:587"},
		{Name: "B", VPNAddr: "2.2.2.2:587"},
	}
	defer func() { connections = nil }()

	// we end up with two "B" entries, that's ok here
	upsertConnection(connection{Name: "B", VPNAddr: "1.1.1.1:587"}, "A")

	if len(connections) != 2 {
		t.Fatalf("expected upsertConnection to only touch the originalName-matched slot, got %d entries: %+v", len(connections), connections)
	}
	if connections[0].Name != "B" || connections[0].VPNAddr != "1.1.1.1:587" {
		t.Errorf("expected slot 0 (originally %q) to become the renamed entry, got %+v", "A", connections[0])
	}
}
