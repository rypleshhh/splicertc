package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHosts(t *testing.T) {
	tests := []struct {
		in       string
		dns, ips int
		wantErr  bool
	}{
		{"localhost,127.0.0.1", 1, 1, false},
		{"vpn.example.com", 1, 0, false},
		{" 203.0.113.5 , 2001:db8::1, vpn.example.com ", 1, 2, false},
		{"", 0, 0, true},
		{" , ", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			dns, ips, err := parseHosts(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(dns) != tt.dns || len(ips) != tt.ips {
				t.Fatalf("got %d names %d IPs, want %d and %d", len(dns), len(ips), tt.dns, tt.ips)
			}
		})
	}
}

func TestWritePEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.pem")
	if err := writePEM(path, 0600, "TEST", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "TEST" || len(block.Bytes) != 3 {
		t.Fatalf("bad PEM: %q", data)
	}

	if err := writePEM(filepath.Join(t.TempDir(), "missing", "x.pem"), 0600, "TEST", nil); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}
