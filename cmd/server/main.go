// Command server is the VPS side of the tunnel. It listens on four TLS
// ports, one per channel:
//
//	reliable  (addr)      SOCKS5-style TCP streams over smux    reliable.go
//	droppable (drop_addr) test channel, frames are only logged  drop.go
//	glue      (glue_addr) game UDP, multipath + dedup           glue.go
//	vpn       (vpn_addr)  whole IP packets into a TUN + NAT     vpn.go, vpn_setup.go
//
// Every connection starts with TLS and the key check from auth.go.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/config"
	"tcp-dormtun/internal/transport"
)

// Config is server-config.json. Command line flags override it.
type Config struct {
	Addr        string `json:"addr,omitempty"`
	DropAddr    string `json:"drop_addr,omitempty"`
	GlueAddr    string `json:"glue_addr,omitempty"`
	VPNAddr     string `json:"vpn_addr,omitempty"`
	VPNTunName  string `json:"vpn_tun_name,omitempty"`
	VPNTunMTU   int    `json:"vpn_tun_mtu,omitempty"`
	VPNSubnet   string `json:"vpn_subnet,omitempty"`
	EgressIface string `json:"egress_iface,omitempty"`
	Cert        string `json:"cert,omitempty"`
	Key         string `json:"key,omitempty"`
	// list of client public keys, see authorized_keys.example.json
	AuthorizedKeysFile string `json:"authorized_keys_file,omitempty"`
	// speed limit server->client in Mbit/s, 0 = off
	VPNDownMbps float64 `json:"vpn_down_mbps,omitempty"`
}

func main() {
	configPath := config.FindFlag(os.Args[1:], "config")
	if configPath == "" {
		configPath = "server-config.json"
	}
	var cfg Config
	foundCfg, err := config.Load(configPath, &cfg)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	addr := flag.String("addr", config.Str(cfg.Addr, ":8443"), "reliable channel listen address")
	dropAddr := flag.String("drop-addr", config.Str(cfg.DropAddr, ":8444"), "droppable channel listen address")
	glueAddr := flag.String("glue-addr", config.Str(cfg.GlueAddr, ":8446"), "glue channel listen address (real captured UDP traffic)")
	vpnAddr := flag.String("vpn-addr", config.Str(cfg.VPNAddr, ":8447"), "full-tunnel VPN channel listen address (all IP traffic, not just UDP)")
	vpnTunName := flag.String("vpn-tun-name", config.Str(cfg.VPNTunName, "dormvpn0"), "server-side TUN interface name for full-tunnel mode")
	vpnTunMTU := flag.Int("vpn-tun-mtu", config.Int(cfg.VPNTunMTU, 1400), "server-side TUN MTU for full-tunnel mode")
	vpnSubnet := flag.String("vpn-subnet", config.Str(cfg.VPNSubnet, "10.66.0.0/24"), "private subnet for the full-tunnel VPN (server=.1, client=.2)")
	egressIface := flag.String("egress-iface", cfg.EgressIface, "interface to MASQUERADE full-tunnel VPN egress traffic out of (empty = auto-detect via `ip route get`)")
	cert := flag.String("cert", config.Str(cfg.Cert, "devcerts/dev.crt"), "TLS cert file")
	key := flag.String("key", config.Str(cfg.Key, "devcerts/dev.key"), "TLS key file")
	authorizedKeysFile := flag.String("authorized-keys-file", cfg.AuthorizedKeysFile, "path to authorized_keys.json, empty = no auth")
	vpnDownMbps := flag.Float64("vpn-down-mbps", cfg.VPNDownMbps, "cap the vpn channel's server->client rate in Mbit/s, a bit below the client's real download speed (0 = no cap)")
	flag.String("config", configPath, "path to a JSON config file (server-config.json by default; explicit flags override its values)")
	flag.Parse()

	if foundCfg {
		log.Printf("loaded config from %s", configPath)
	}
	vpnDownRate = *vpnDownMbps
	if vpnDownRate > 0 {
		log.Printf("vpn: shaping server->client to %.1f Mbit/s", vpnDownRate)
	}

	if fp, err := transport.LoadCertFingerprint(*cert); err != nil {
		log.Printf("could not compute cert fingerprint for pinning: %v", err)
	} else {
		log.Printf("cert fingerprint (put this in the client's server_pin to enable pinning): %x", fp)
	}

	if *authorizedKeysFile != "" {
		keys, err := auth.LoadAuthorizedKeys(*authorizedKeysFile)
		if err != nil {
			log.Fatalf("load authorized keys: %v", err)
		}
		authorizedKeys = keys
		log.Printf("client authentication enabled (%s)", *authorizedKeysFile)
	} else {
		log.Println("WARNING: no authorized_keys_file, anyone can connect to this server!")
	}

	ln := listen("reliable", *addr, *cert, *key)
	dropLn := listen("droppable", *dropAddr, *cert, *key)
	glueLn := listen("glue", *glueAddr, *cert, *key)
	vpnLn := listen("vpn", *vpnAddr, *cert, *key)

	vpnDev, vpnNetwork, err := setupVPNTun(*vpnTunName, *vpnTunMTU, *vpnSubnet, *egressIface)
	if err != nil {
		log.Fatalf("vpn tun setup: %v", err)
	}
	go vpnTunReader(vpnDev)
	go janitor()

	go acceptLoop("vpn", vpnLn, func(c net.Conn) { handleVPNConn(c, vpnDev, vpnNetwork) })
	go acceptLoop("droppable", dropLn, handleDroppableConn)
	go acceptLoop("glue", glueLn, handleGlueConn)
	acceptLoop("reliable", ln, handleConn)
}

func listen(name, addr, cert, key string) net.Listener {
	ln, err := transport.Listen(addr, cert, key)
	if err != nil {
		log.Fatalf("%s listen: %v", name, err)
	}
	log.Printf("%s channel listening on %s", name, addr)
	return ln
}

// acceptLoop runs handle in its own goroutine for every connection.
func acceptLoop(name string, ln net.Listener, handle func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("%s accept: %v", name, err)
			// e.g. out of file descriptors, don't spin at 100% CPU
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handle(conn)
	}
}

// janitor periodically removes state nobody uses any more.
func janitor() {
	for range time.Tick(janitorInterval) {
		now := time.Now()
		cleanupGlue(now)
		cleanupDrop(now)
		cleanupAuthFailures(now)
	}
}
