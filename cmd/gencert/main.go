// Command gencert writes a self-signed TLS cert/key pair to devcerts/.
// Run it once and keep the result — the tunnel's own client-side pinning
// (server_pin/pin_file) is what actually authenticates the server, not
// this cert's chain, so there's no need to regenerate it regularly; in
// fact regenerating it changes its fingerprint and breaks every existing
// client's pin until they update it. For a real deployment, generate
// this once and mount the resulting devcerts/ into the server container
// as a persistent volume (see docker-compose.yml) instead of letting the
// Docker build regenerate a fresh one on every rebuild.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		log.Fatalf("serial: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		// Long-lived on purpose: this project's client never does normal
		// chain/expiry validation against this cert (see transport.Dial's
		// pin path and -insecure) — it's checked only by exact fingerprint
		// match or not checked at all. A short expiry would add nothing
		// here and would be one more reason to regenerate (and thereby
		// change the fingerprint, breaking every client's server_pin/
		// pin_file) for no security benefit.
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}

	if err := os.MkdirAll("devcerts", 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	certOut, err := os.Create("devcerts/dev.crt")
	if err != nil {
		log.Fatalf("create dev.crt: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	keyOut, err := os.Create("devcerts/dev.key")
	if err != nil {
		log.Fatalf("create dev.key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	log.Println("wrote devcerts/dev.crt and devcerts/dev.key")
}
