// Command server is the VPS side of the tunnel. It listens on up to four
// TLS ports, one per channel (any of them can be set to "off"):
//
//	reliable  (addr)      SOCKS5-style TCP streams over smux    reliable.go
//	droppable (drop_addr) test channel, frames are only logged  drop.go
//	glue      (glue_addr) game UDP, multipath + dedup           glue.go
//	vpn       (vpn_addr)  whole IP packets into a TUN + NAT     vpn.go, vpn_setup.go
//
// Every connection starts with TLS and the key check from auth.go.
// Where clients may connect is decided by internal/egress.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/config"
	"tcp-dormtun/internal/egress"
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
	// let clients reach private networks (10/8, 172.16/12, 192.168/16,
	// 100.64/10) through the tunnel; off by default
	AllowPrivateDestinations bool `json:"allow_private_destinations,omitempty"`
}

// channelOff as a listen address disables that channel.
const channelOff = "off"

// destinations is where reliable and glue may connect for a client.
// main replaces it with the configured policy; the zero value (used in
// tests) blocks private networks.
var destinations = &egress.Policy{}

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

	addr := flag.String("addr", config.Str(cfg.Addr, ":8443"), "reliable channel listen address (\"off\" disables it)")
	dropAddr := flag.String("drop-addr", config.Str(cfg.DropAddr, ":8444"), "droppable channel listen address (\"off\" disables it)")
	glueAddr := flag.String("glue-addr", config.Str(cfg.GlueAddr, ":8446"), "glue channel listen address, real captured UDP traffic (\"off\" disables it)")
	vpnAddr := flag.String("vpn-addr", config.Str(cfg.VPNAddr, ":8447"), "full-tunnel VPN channel listen address (\"off\" disables it, then no TUN/iptables are needed)")
	vpnTunName := flag.String("vpn-tun-name", config.Str(cfg.VPNTunName, "dormvpn0"), "server-side TUN interface name for full-tunnel mode")
	vpnTunMTU := flag.Int("vpn-tun-mtu", config.Int(cfg.VPNTunMTU, 1400), "server-side TUN MTU for full-tunnel mode")
	vpnSubnet := flag.String("vpn-subnet", config.Str(cfg.VPNSubnet, "10.66.0.0/24"), "private subnet for the full-tunnel VPN (server=.1, client=.2)")
	egressIface := flag.String("egress-iface", cfg.EgressIface, "interface to MASQUERADE full-tunnel VPN egress traffic out of (empty = auto-detect via `ip route get`)")
	cert := flag.String("cert", config.Str(cfg.Cert, "devcerts/dev.crt"), "TLS cert file")
	key := flag.String("key", config.Str(cfg.Key, "devcerts/dev.key"), "TLS key file")
	authorizedKeysFile := flag.String("authorized-keys-file", cfg.AuthorizedKeysFile, "path to authorized_keys.json, empty = no auth")
	vpnDownMbps := flag.Float64("vpn-down-mbps", cfg.VPNDownMbps, "cap the vpn channel's server->client rate in Mbit/s, a bit below the client's real download speed (0 = no cap)")
	allowPrivate := flag.Bool("allow-private-destinations", cfg.AllowPrivateDestinations, "let clients reach private networks (10/8, 172.16/12, 192.168/16, 100.64/10) through the tunnel")
	// only a command line flag on purpose, so it can't be switched on by
	// a config file by accident
	allowUnauth := flag.Bool("allow-unauthenticated", false, "start without authorized_keys_file (anyone can use the server as a proxy!), for local tests only")
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

	// fail closed: a server without keys is an open proxy, so a missing
	// line in the config must not silently start one
	switch {
	case *authorizedKeysFile != "":
		keys, err := auth.LoadAuthorizedKeys(*authorizedKeysFile)
		if err != nil {
			log.Fatalf("load authorized keys: %v", err)
		}
		authorizedKeys = keys
		log.Printf("client authentication enabled (%s)", *authorizedKeysFile)
	case *allowUnauth:
		log.Println("WARNING: -allow-unauthenticated: anyone can connect to this server!")
	default:
		log.Fatalf("authorized_keys_file is not set. Without it anyone can use this server as a proxy; " +
			"set it in server-config.json (see authorized_keys.example.json), or pass -allow-unauthenticated for a local test")
	}

	destinations, err = egress.New(*allowPrivate)
	if err != nil {
		log.Fatalf("egress policy: %v", err)
	}
	if *allowPrivate {
		log.Println("WARNING: allow_private_destinations is on, clients can reach private networks through the tunnel")
	}

	go janitor()
	var running []func()

	if *vpnAddr != channelOff {
		vpnLn := listen("vpn", *vpnAddr, *cert, *key)
		vpnDev, vpnNetwork, err := setupVPNTun(*vpnTunName, *vpnTunMTU, *vpnSubnet, *egressIface, *allowPrivate)
		if err != nil {
			log.Fatalf("vpn tun setup: %v", err)
		}
		go vpnTunReader(vpnDev)
		running = append(running, func() {
			acceptLoop("vpn", vpnLn, func(c net.Conn) { handleVPNConn(c, vpnDev, vpnNetwork) })
		})
	}
	running = addChannel(running, "reliable", *addr, *cert, *key, handleConn)
	running = addChannel(running, "droppable", *dropAddr, *cert, *key, handleDroppableConn)
	running = addChannel(running, "glue", *glueAddr, *cert, *key, handleGlueConn)

	if len(running) == 0 {
		log.Fatalf("all channels are off, nothing to do")
	}
	for _, run := range running[1:] {
		go run()
	}
	running[0]() // the first accept loop keeps main alive
}

// addChannel starts listening unless addr is "off" and returns the list
// of accept loops with this one added.
func addChannel(running []func(), name, addr, cert, key string, handle func(net.Conn)) []func() {
	if addr == channelOff {
		log.Printf("%s channel is off", name)
		return running
	}
	ln := listen(name, addr, cert, key)
	return append(running, func() { acceptLoop(name, ln, handle) })
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
		// own addresses can change (DHCP); on error the old list stays
		if err := destinations.Refresh(); err != nil {
			log.Printf("egress: %v", err)
		}
	}
}
