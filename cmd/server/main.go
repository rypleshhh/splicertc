// Command server is the VPS side of the tunnel. It listens on up to four
// TLS ports, one per channel (any of them can be set to "off"):
//
//	reliable  (addr)      SOCKS5-style TCP streams over smux    reliable.go
//	droppable (drop_addr) test channel, frames are only logged  drop.go (off by default)
//	glue      (glue_addr) game UDP, multipath + dedup           glue.go
//	vpn       (vpn_addr)  whole IP packets into a TUN + NAT     vpn.go, vpn_setup.go
//
// Every connection starts with TLS and the key check from auth.go.
// Where clients may connect is decided by internal/egress.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	// public IPs of this server that are not on any interface (clouds
	// with 1:1 NAT), so clients can't reach the server through them
	PublicIPs []string `json:"public_ips,omitempty"`
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
	// a debug channel that logs every frame, so only on when asked for
	dropAddr := flag.String("drop-addr", config.Str(cfg.DropAddr, channelOff), "droppable test channel listen address, e.g. :8444 (\"off\" by default)")
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
	publicIPs := flag.String("public-ips", strings.Join(cfg.PublicIPs, ","), "comma-separated public IPs of this server that are not on any interface (1:1 NAT clouds), clients are not let through to them")
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

	if err := checkCertFiles(*cert, *key); err != nil {
		log.Fatal(err)
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
	ownIPs, err := parseIPList(*publicIPs)
	if err != nil {
		log.Fatalf("public_ips: %v", err)
	}
	if len(ownIPs) > 0 {
		destinations.AddOwn(ownIPs...)
		log.Printf("egress: also blocking own public IPs %s", *publicIPs)
	}

	// stop on docker stop / Ctrl+C, so the iptables rules get removed
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// listen on everything first: a failure here must not leave
	// iptables rules behind
	type channel struct {
		name   string
		ln     net.Listener
		handle func(net.Conn)
	}
	var channels []channel
	add := func(name, addr string, handle func(net.Conn)) {
		if addr == channelOff {
			log.Printf("%s channel is off", name)
			return
		}
		channels = append(channels, channel{name, listen(name, addr, *cert, *key), handle})
	}
	add("reliable", *addr, handleConn)
	add("droppable", *dropAddr, handleDroppableConn)
	add("glue", *glueAddr, handleGlueConn)
	var vpnLn net.Listener
	if *vpnAddr != channelOff {
		vpnLn = listen("vpn", *vpnAddr, *cert, *key)
	}
	if len(channels) == 0 && vpnLn == nil {
		log.Fatalf("all channels are off, nothing to do")
	}

	vpnCleanup := func() {}
	if vpnLn != nil {
		dev, vn, cleanup, err := setupVPNTun(vpnSetup{
			tunName:      *vpnTunName,
			mtu:          *vpnTunMTU,
			subnet:       *vpnSubnet,
			egressIface:  *egressIface,
			allowPrivate: *allowPrivate,
			publicIPs:    ownIPs,
		})
		if err != nil {
			log.Fatalf("vpn tun setup: %v", err)
		}
		vpnCleanup = cleanup
		go vpnTunReader(dev)
		channels = append(channels, channel{"vpn", vpnLn, func(c net.Conn) { handleVPNConn(c, dev, vn) }})
	}

	go janitor()
	for _, ch := range channels {
		go acceptLoop(ch.name, ch.ln, ch.handle)
	}

	<-ctx.Done()
	log.Printf("shutting down")
	for _, ch := range channels {
		ch.ln.Close()
	}
	vpnCleanup()
}

// checkCertFiles gives a hint instead of a bare "no such file" when the
// TLS cert is missing (it's not in the image, it must be mounted).
func checkCertFiles(files ...string) error {
	for _, f := range files {
		if _, err := os.Stat(f); errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("TLS cert/key %s not found: run `go run ./cmd/gencert` once on the host "+
				"(it writes devcerts/dev.crt and devcerts/dev.key), and in docker make sure devcerts/ is mounted "+
				"to /app/devcerts (see docker-compose.yml)", f)
		}
	}
	return nil
}

// parseIPList parses a comma-separated list of IP addresses.
func parseIPList(s string) ([]net.IP, error) {
	var ips []net.IP
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP address", part)
		}
		ips = append(ips, ip)
	}
	return ips, nil
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
		if errors.Is(err, net.ErrClosed) {
			return // shutdown
		}
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
