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
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	force := flag.Bool("force", false, "overwrite an existing devcerts/dev.crt (every client's pin has to be updated after that)")
	// clients pin the fingerprint, so the names only matter for tools that
	// check them; the default is fine for pin-only setups
	hosts := flag.String("host", "localhost,127.0.0.1", "comma-separated DNS names and/or IPs of the server for the cert (the first DNS name, or IP if there is none, is also the CN)")
	flag.Parse()
	if _, err := os.Stat("devcerts/dev.crt"); err == nil && !*force {
		log.Fatalf("devcerts/dev.crt already exists; a new cert breaks the clients' pins. Use -force if you really want a new one")
	}

	dnsNames, ips, err := parseHosts(*hosts)
	if err != nil {
		log.Fatalf("-host: %v", err)
	}
	var cn string
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	} else {
		cn = ips[0].String()
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
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		// 10 years, clients only check the fingerprint anyway
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}

	if err := os.MkdirAll("devcerts", 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}
	if err := writePEM("devcerts/dev.crt", 0644, "CERTIFICATE", der); err != nil {
		log.Fatal(err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	// the private key must not be readable by other users of the VPS
	if err := writePEM("devcerts/dev.key", 0600, "EC PRIVATE KEY", keyBytes); err != nil {
		log.Fatal(err)
	}

	log.Printf("wrote devcerts/dev.crt and devcerts/dev.key for %s", *hosts)
}

// parseHosts splits "a.example.com,203.0.113.5" into DNS names and IPs.
func parseHosts(s string) (dnsNames []string, ips []net.IP, err error) {
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("no host names or IPs given")
	}
	return dnsNames, ips, nil
}

// writePEM writes one PEM block. A half-written key or cert would only
// show up later as a TLS error on the server, so every error counts.
func writePEM(path string, perm os.FileMode, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
