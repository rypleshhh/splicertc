package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/config"
)

func TestLoadClientKey(t *testing.T) {
	_, seedA, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, seedB, _ := auth.GenerateKeypair()
	_, seedC, _ := auth.GenerateKeypair()
	keyFile := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(keyFile, []byte(auth.EncodeKey(seedB)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	short := auth.EncodeKey(seedA[:16])

	cases := []struct {
		name              string
		env, file, inline string
		want              []byte
		wantErr           string
	}{
		{"env wins", auth.EncodeKey(seedA), keyFile, auth.EncodeKey(seedC), seedA, ""},
		{"file before inline", "", keyFile, auth.EncodeKey(seedC), seedB, ""},
		{"inline", "", "", auth.EncodeKey(seedC), seedC, ""},
		{"none", "", "", "", nil, clientKeyEnv},
		{"env bad base64", "!!!", "", "", nil, clientKeyEnv},
		{"env short", short, "", "", nil, "32-byte"},
		{"inline short", "", "", short, nil, "32-byte"},
		{"missing file", "", filepath.Join(t.TempDir(), "nope"), "", nil, "read client key file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := loadClientKey(c.env, c.file, c.inline)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("got err %v, want one containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(c.want) {
				t.Fatal("wrong key returned")
			}
		})
	}
}

// The error for a missing key names every way to set it.
func TestNoClientKeyMessage(t *testing.T) {
	for _, s := range []string{"client_key_file", "client_key", "SPLICERTC_CLIENT_KEY"} {
		if !strings.Contains(errNoClientKey.Error(), s) {
			t.Errorf("message doesn't mention %s", s)
		}
	}
}

func TestResolver(t *testing.T) {
	lookups := 0
	r := newResolver()
	r.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		switch host {
		case "vpn.example.com":
			// round-robin: a second lookup would give another order
			ips := []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.IPv4(203, 0, 113, byte(lookups))}}
			return ips, nil
		case "v6only.example.com":
			return []net.IPAddr{{IP: net.ParseIP("2001:db8::2")}}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct {
		name, addr, wantAddr, wantName, wantErr string
	}{
		{"name, IPv4 preferred", "vpn.example.com:587", "203.0.113.1:587", "vpn.example.com", ""},
		{"same host, same IP", "vpn.example.com:993", "203.0.113.1:993", "vpn.example.com", ""},
		{"IPv4 literal", "198.51.100.7:443", "198.51.100.7:443", "", ""},
		{"IPv6 literal", "[2001:db8::9]:443", "[2001:db8::9]:443", "", ""},
		{"IPv6 only", "v6only.example.com:443", "[2001:db8::2]:443", "v6only.example.com", ""},
		{"lookup fails", "bad.example.com:443", "", "", "resolve bad.example.com"},
		{"no port", "vpn.example.com", "", "", "server address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, name, err := r.resolve(c.addr)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("got err %v, want one containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if addr != c.wantAddr || name != c.wantName {
				t.Fatalf("got %s %q, want %s %q", addr, name, c.wantAddr, c.wantName)
			}
		})
	}
	// vpn.example.com was looked up once, the rest are the other hosts
	if lookups != 3 {
		t.Fatalf("%d lookups, want 3", lookups)
	}
}

func TestEndpointServerName(t *testing.T) {
	r := newResolver()
	r.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.IPv4(203, 0, 113, 1)}}, nil
	}
	cases := []struct {
		name, addr, serverName, wantSNI string
	}{
		{"host name by default", "vpn.example.com:587", "", "vpn.example.com"},
		{"server_name wins", "vpn.example.com:587", "cert.example.com", "cert.example.com"},
		{"IP address", "203.0.113.1:587", "", ""},
		{"IP with server_name", "203.0.113.1:587", "cert.example.com", "cert.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep, err := r.endpoint(c.addr, c.serverName, true)
			if err != nil {
				t.Fatal(err)
			}
			if ep.addr != "203.0.113.1:587" || ep.dc.ServerName != c.wantSNI || !ep.dc.Insecure {
				t.Fatalf("got %+v, want SNI %q", ep, c.wantSNI)
			}
		})
	}
}

func TestVPNAddresses(t *testing.T) {
	cases := []struct {
		subnet, local, gateway string
		ok                     bool
	}{
		{"10.66.0.0/24", "10.66.0.2", "10.66.0.1", true},
		{"10.66.0.77/24", "10.66.0.2", "10.66.0.1", true},
		{"172.20.4.0/30", "172.20.4.2", "172.20.4.1", true},
		{"10.66.0.0/31", "", "", false},
		{"fd00::/64", "", "", false},
		{"10.66.0.0", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.subnet, func(t *testing.T) {
			local, gw, err := vpnAddresses(c.subnet)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if c.ok && (local.String() != c.local || gw.String() != c.gateway) {
				t.Fatalf("got %s/%s, want %s/%s", local, gw, c.local, c.gateway)
			}
		})
	}
}

// The config loader rejects unknown fields, so every field the tray
// writes must exist in Config.
func TestConfigAcceptsTrayFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-config.json")
	data := `{
		"mode": "vpn",
		"vpn_addr": "vpn.example.com:587",
		"vpn_tun_name": "dormvpn0",
		"vpn_tun_mtu": 1400,
		"vpn_subnet": "10.66.0.0/24",
		"server_name": "vpn.example.com",
		"pin_file": "server.pin",
		"server_pin": "",
		"insecure": false,
		"game_processes": ["deadlock.exe"],
		"glue_addr": "vpn.example.com:993",
		"client_key": "AAAA"
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if _, err := config.Load(path, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.VPNSubnet != "10.66.0.0/24" || cfg.ServerName != "vpn.example.com" {
		t.Fatalf("new fields not loaded: %+v", cfg)
	}
}
