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
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
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
