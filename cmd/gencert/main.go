// Command gencert writes a self-signed cert to devcerts/. Generate it once,
// a new cert breaks the clients' pinned fingerprint.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	force := flag.Bool("force", false, "overwrite an existing devcerts/dev.crt (every client's pin has to be updated after that)")
	flag.Parse()
	if _, err := os.Stat("devcerts/dev.crt"); err == nil && !*force {
		log.Fatalf("devcerts/dev.crt already exists; a new cert breaks the clients' pins. Use -force if you really want a new one")
	}

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
		// 10 years, clients only check the fingerprint anyway
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

	certOut, err := os.OpenFile("devcerts/dev.crt", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("create dev.crt: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	// the private key must not be readable by other users of the VPS
	keyOut, err := os.OpenFile("devcerts/dev.key", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("create dev.key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	log.Println("wrote devcerts/dev.crt and devcerts/dev.key")
}
