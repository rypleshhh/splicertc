package auth

import (
	"net"
	"os"
	"sync"
	"testing"
)

func TestHandshakeSucceedsWithMatchingKey(t *testing.T) {
	key := []byte("shared-secret-key-material")
	serverConn, clientConn := net.Pipe()

	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = ServerHandshake(serverConn, key)
	}()

	clientErr := ClientHandshake(clientConn, key)
	wg.Wait()

	if clientErr != nil {
		t.Errorf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Errorf("server handshake: %v", serverErr)
	}
}

func TestHandshakeFailsWithWrongKey(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = ServerHandshake(serverConn, []byte("server-key"))
	}()

	_ = ClientHandshake(clientConn, []byte("wrong-key"))
	wg.Wait()

	if serverErr == nil {
		t.Error("expected server to reject a client with the wrong key")
	}
}

func TestLoadKeyTrimsAndHashes(t *testing.T) {
	f, err := os.CreateTemp("", "dormtun-key-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("  my passphrase  \n")
	f.Close()

	key, err := LoadKey(f.Name())
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected a 32-byte derived key, got %d bytes", len(key))
	}

	// Same content, different whitespace, should derive the same key.
	f2, _ := os.CreateTemp("", "dormtun-key-*")
	defer os.Remove(f2.Name())
	f2.WriteString("my passphrase")
	f2.Close()
	key2, err := LoadKey(f2.Name())
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if string(key) != string(key2) {
		t.Error("expected whitespace-trimmed content to derive the same key")
	}
}

func TestLoadKeyRejectsEmpty(t *testing.T) {
	f, _ := os.CreateTemp("", "dormtun-key-*")
	defer os.Remove(f.Name())
	f.WriteString("   \n")
	f.Close()

	if _, err := LoadKey(f.Name()); err == nil {
		t.Error("expected LoadKey to reject an effectively empty key file")
	}
}
