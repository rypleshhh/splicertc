package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// selfSignedCert builds a throwaway self-signed cert/key pair entirely
// in memory, the same shape internal/transport's own tests use.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// tlsPair opens one real TLS connection over loopback TCP and returns
// both ends with their handshake already complete — what
// ServerHandshake/ClientHandshake actually run over in production
// (auth.go requires a *tls.Conn, so net.Pipe won't do here).
func tlsPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	serverCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		if tc, ok := c.(*tls.Conn); ok {
			if err := tc.Handshake(); err != nil {
				errCh <- err
				return
			}
		}
		serverCh <- c
	}()

	clientConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
		return nil, nil
	case serverConn := <-serverCh:
		t.Cleanup(func() { serverConn.Close(); clientConn.Close() })
		return serverConn, clientConn
	}
}

func TestHandshakeSucceedsWithAuthorizedKey(t *testing.T) {
	pub, seed, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	keys := &AuthorizedKeys{byKey: map[string]string{string(pub): "friend1"}}

	serverConn, clientConn := tlsPair(t)

	var wg sync.WaitGroup
	var serverErr error
	var name string
	wg.Add(1)
	go func() {
		defer wg.Done()
		name, serverErr = ServerHandshake(serverConn, keys)
	}()

	clientErr := ClientHandshake(clientConn, seed)
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	if name != "friend1" {
		t.Errorf("expected server to identify the caller as %q, got %q", "friend1", name)
	}
}

// TestHandshakeFailsWithUnauthorizedKey uses a real, validly-signed
// Ed25519 identity that was simply never added to the server's list —
// proving possession of *some* key pair isn't enough, it has to be one
// the server was told to trust.
func TestHandshakeFailsWithUnauthorizedKey(t *testing.T) {
	_, seed, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	keys := &AuthorizedKeys{byKey: map[string]string{}}

	serverConn, clientConn := tlsPair(t)

	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, serverErr = ServerHandshake(serverConn, keys)
	}()

	_ = ClientHandshake(clientConn, seed)
	wg.Wait()

	if serverErr == nil {
		t.Error("expected server to reject a client whose public key isn't in authorized_keys")
	}
}

// TestHandshakeBindsToTLSSession is the direct regression test for the
// exporter binding in bindingMessage: it proves a signature computed
// for one TLS connection is invalid on a different one, even given the
// identical challenge bytes on both — the property that defeats a party
// able to relay a challenge between two separate connections to the
// real server without ever holding the private key itself.
func TestHandshakeBindsToTLSSession(t *testing.T) {
	_, seed, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	_, connA := tlsPair(t)
	_, connB := tlsPair(t)
	tcA, ok := connA.(*tls.Conn)
	if !ok {
		t.Fatal("connA is not a *tls.Conn")
	}
	tcB, ok := connB.(*tls.Conn)
	if !ok {
		t.Fatal("connB is not a *tls.Conn")
	}

	forcedChallenge := make([]byte, challengeSize) // identical on both, on purpose

	msgA, err := bindingMessage(tcA, forcedChallenge)
	if err != nil {
		t.Fatalf("bindingMessage A: %v", err)
	}
	msgB, err := bindingMessage(tcB, forcedChallenge)
	if err != nil {
		t.Fatalf("bindingMessage B: %v", err)
	}
	if string(msgA) == string(msgB) {
		t.Fatal("expected two different TLS connections to produce different binding messages for the same challenge")
	}

	sigA := ed25519.Sign(priv, msgA)
	if !ed25519.Verify(pub, msgA, sigA) {
		t.Fatal("sanity check failed: signature didn't verify against its own message")
	}
	if ed25519.Verify(pub, msgB, sigA) {
		t.Fatal("signature computed for connection A verified against connection B's message — TLS session binding is not working")
	}
}

func TestGenerateKeypairRoundTrip(t *testing.T) {
	pub, seed, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	decodedPub, err := DecodeKey(EncodeKey(pub))
	if err != nil {
		t.Fatalf("DecodeKey(EncodeKey(pub)): %v", err)
	}
	if string(decodedPub) != string(pub) {
		t.Error("public key didn't round-trip through EncodeKey/DecodeKey")
	}

	decodedSeed, err := DecodeKey(EncodeKey(seed))
	if err != nil {
		t.Fatalf("DecodeKey(EncodeKey(seed)): %v", err)
	}
	priv := ed25519.NewKeyFromSeed(decodedSeed)
	if string(priv.Public().(ed25519.PublicKey)) != string(pub) {
		t.Error("seed round-tripped through EncodeKey/DecodeKey doesn't reconstruct the original public key")
	}
}

func TestLoadAuthorizedKeysParsesFile(t *testing.T) {
	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	f, err := os.CreateTemp("", "authorized-keys-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(`[{"name":"friend1","public_key":"` + EncodeKey(pub) + `"}]`)
	f.Close()

	keys, err := LoadAuthorizedKeys(f.Name())
	if err != nil {
		t.Fatalf("LoadAuthorizedKeys: %v", err)
	}
	if name, ok := keys.byKey[string(pub)]; !ok || name != "friend1" {
		t.Errorf("expected pub to map to %q, got %q (found=%v)", "friend1", name, ok)
	}
}

func TestLoadAuthorizedKeysRejectsMalformedEntry(t *testing.T) {
	f, err := os.CreateTemp("", "authorized-keys-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(`[{"name":"bad","public_key":"not-valid-base64!!"}]`)
	f.Close()

	if _, err := LoadAuthorizedKeys(f.Name()); err == nil {
		t.Error("expected LoadAuthorizedKeys to reject an entry with an invalid public key")
	}
}

func TestLoadClientKeyRejectsWrongLength(t *testing.T) {
	f, err := os.CreateTemp("", "client-key-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(base64.StdEncoding.EncodeToString([]byte("too-short")))
	f.Close()

	if _, err := LoadClientKey(f.Name()); err == nil {
		t.Error("expected LoadClientKey to reject a seed that isn't 32 bytes")
	}
}
