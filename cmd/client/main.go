// Command client is the Windows side of the tunnel. Modes (-mode):
//
//	socks5    local SOCKS5 proxy over the reliable channel      socks.go
//	droptest  test frames over the droppable channel            droptest.go
//	tun       all UDP from a TUN adapter over glue (multipath)  tun.go
//	vpn       all IPv4 over one TLS stream, games over glue     vpn.go
//
// vpn mode is the main one, the tray app runs it.
package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"tcp-dormtun/internal/config"
	"tcp-dormtun/internal/transport"
)

// Config is client-config.json. Command line flags override it.
type Config struct {
	Mode               string `json:"mode,omitempty"`
	Listen             string `json:"listen,omitempty"`
	Server             string `json:"server,omitempty"`
	DropAddr           string `json:"drop_addr,omitempty"`
	GlueAddr           string `json:"glue_addr,omitempty"`
	TunName            string `json:"tun_name,omitempty"`
	TunMTU             int    `json:"tun_mtu,omitempty"`
	TunPaths           int    `json:"tun_paths,omitempty"`
	TunMeasure         bool   `json:"tun_measure,omitempty"`
	TunMeasureInterval string `json:"tun_measure_interval,omitempty"` // e.g. "33ms"
	VPNAddr            string `json:"vpn_addr,omitempty"`
	VPNTunName         string `json:"vpn_tun_name,omitempty"`
	VPNTunMTU          int    `json:"vpn_tun_mtu,omitempty"`
	// must match the server; the client is .2, the gateway .1
	VPNSubnet string `json:"vpn_subnet,omitempty"`
	// UDP from these processes goes through glue (multipath)
	GameProcesses []string `json:"game_processes,omitempty"`
	// number of glue paths, 3 by default
	GamePaths int `json:"game_paths,omitempty"`
	// speed limit client->server in Mbit/s, 0 = off
	VPNUpMbps    float64 `json:"vpn_up_mbps,omitempty"`
	DropCount    int     `json:"drop_count,omitempty"`
	DropInterval string  `json:"drop_interval,omitempty"` // e.g. "33ms"
	DropPaths    int     `json:"drop_paths,omitempty"`
	Insecure     bool    `json:"insecure,omitempty"`
	// SHA-256 of the server cert (the server prints it on start)
	ServerPin string `json:"server_pin,omitempty"`
	// name the server certificate is checked against (and SNI). Empty
	// means the host from the address. Needed for a CA certificate when
	// the address is an IP.
	ServerName string `json:"server_name,omitempty"`
	// file to save the server cert fingerprint on first connect (TOFU),
	// ignored if ServerPin is set
	PinFile string `json:"pin_file,omitempty"`
	// file with the client private key (from cmd/genkey)
	ClientKeyFile string `json:"client_key_file,omitempty"`
	// or the same key directly in the config. The SPLICERTC_CLIENT_KEY
	// environment variable overrides both.
	ClientKey string `json:"client_key,omitempty"`
}

// parseGameProcesses splits the comma list and lowercases the names.
func parseGameProcesses(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Fatalf("config: invalid duration %q: %v", s, err)
	}
	return d
}

func main() {
	configPath := config.FindFlag(os.Args[1:], "config")
	if configPath == "" {
		configPath = "client-config.json"
	}
	var cfg Config
	foundCfg, err := config.Load(configPath, &cfg)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	mode := flag.String("mode", config.Str(cfg.Mode, "socks5"), "socks5 (default), droptest, tun, or vpn")
	listenAddr := flag.String("listen", config.Str(cfg.Listen, "127.0.0.1:1080"), "SOCKS5 listen address")
	serverAddr := flag.String("server", config.Str(cfg.Server, "127.0.0.1:8443"), "tunnel server address")
	dropAddr := flag.String("drop-addr", config.Str(cfg.DropAddr, "127.0.0.1:8444"), "droppable channel address (droptest mode)")
	glueAddr := flag.String("glue-addr", config.Str(cfg.GlueAddr, "127.0.0.1:8446"), "glue channel address (tun mode)")
	tunName := flag.String("tun-name", config.Str(cfg.TunName, "dormtun0"), "TUN interface name (tun mode)")
	tunMTU := flag.Int("tun-mtu", config.Int(cfg.TunMTU, 1420), "TUN interface MTU (tun mode)")
	tunPaths := flag.Int("tun-paths", config.Int(cfg.TunPaths, 1), "tun mode: number of parallel duplicated paths (1 = no duplication)")
	tunMeasure := flag.Bool("tun-measure", cfg.TunMeasure, "tun mode: send measurement pings and print RTT/jitter/loss periodically")
	tunMeasureInterval := flag.Duration("tun-measure-interval", parseDurationOr(cfg.TunMeasureInterval, 33*time.Millisecond), "tun mode: spacing between measurement pings")
	vpnAddr := flag.String("vpn-addr", config.Str(cfg.VPNAddr, "127.0.0.1:8447"), "full-tunnel VPN channel address (vpn mode)")
	vpnTunName := flag.String("vpn-tun-name", config.Str(cfg.VPNTunName, "dormvpn0"), "TUN interface name (vpn mode)")
	vpnTunMTU := flag.Int("vpn-tun-mtu", config.Int(cfg.VPNTunMTU, 1400), "TUN interface MTU (vpn mode)")
	vpnSubnet := flag.String("vpn-subnet", config.Str(cfg.VPNSubnet, "10.66.0.0/24"), "vpn mode: tunnel subnet, must match the server (client .2, gateway .1)")
	dropCount := flag.Int("drop-count", cfg.DropCount, "droptest: if >0, send this many frames at -drop-interval spacing instead of the fixed delay demo")
	dropInterval := flag.Duration("drop-interval", parseDurationOr(cfg.DropInterval, 33*time.Millisecond), "droptest: spacing between frames in stress mode (33ms ~ 30 ticks/sec, like a game sending state updates)")
	dropPaths := flag.Int("drop-paths", config.Int(cfg.DropPaths, 1), "droptest stress mode: number of parallel TLS connections to duplicate each frame across")
	insecure := flag.Bool("insecure", cfg.Insecure, "skip TLS cert verification (dev only)")
	serverName := flag.String("server-name", cfg.ServerName, "name the server certificate must be valid for, also sent as SNI (default: the host from the server address)")
	serverPin := flag.String("server-pin", cfg.ServerPin, "SHA-256 (hex) of the server certificate, connection fails if it doesn't match")
	pinFile := flag.String("pin-file", cfg.PinFile, "trust-on-first-use: path to save/read the server's certificate fingerprint automatically, instead of copying -server-pin by hand (ignored if -server-pin is set)")
	gameProcessesFlag := flag.String("game-processes", strings.Join(cfg.GameProcesses, ","), "vpn mode: comma-separated executable names (e.g. deadlock.exe) whose UDP traffic gets routed through the glue channel with multipath duplication instead of the single vpn stream")
	gamePaths := flag.Int("game-paths", config.Int(cfg.GamePaths, 0), "vpn mode: multipath duplication factor for -game-processes UDP traffic (0 = default of 3 if -game-processes is set)")
	vpnUpMbps := flag.Float64("vpn-up-mbps", cfg.VPNUpMbps, "vpn mode: cap the client->server rate in Mbit/s, a bit below the real upload speed (0 = no cap)")
	clientKeyFile := flag.String("client-key-file", cfg.ClientKeyFile, "file with the client private key (from cmd/genkey); the SPLICERTC_CLIENT_KEY environment variable overrides it")
	flag.String("config", configPath, "path to a JSON config file (client-config.json by default; explicit flags override its values)")
	flag.Parse()

	if foundCfg {
		log.Printf("loaded config from %s", configPath)
	}

	key, err := loadClientKey(os.Getenv(clientKeyEnv), *clientKeyFile, cfg.ClientKey)
	if err != nil {
		log.Fatal(err)
	}

	// Every server address is resolved once here and the same IP is
	// used for all connections (see resolver).
	res := newResolver()
	resolveEndpoint := func(addr string) endpoint {
		ep, err := res.endpoint(addr, *serverName, *insecure)
		if err != nil {
			log.Fatalf("%v", err)
		}
		if ep.addr != addr {
			log.Printf("resolved %s to %s", addr, ep.addr)
		}
		return ep
	}
	gameProcesses := parseGameProcesses(*gameProcessesFlag)
	var srv, glueSrv endpoint
	switch *mode {
	case "vpn":
		local, gateway, err := vpnAddresses(*vpnSubnet)
		if err != nil {
			log.Fatalf("%v", err)
		}
		log.Printf("vpn subnet %s: client %s, gateway %s", *vpnSubnet, local, gateway)
		srv = resolveEndpoint(*vpnAddr)
		if len(gameProcesses) > 0 {
			glueSrv = resolveEndpoint(*glueAddr)
		}
	case "tun":
		srv = resolveEndpoint(*glueAddr)
	case "droptest":
		srv = resolveEndpoint(*dropAddr)
	default:
		srv = resolveEndpoint(*serverAddr)
	}

	var pin []byte
	switch {
	case *serverPin != "":
		p, err := transport.ParsePin(*serverPin)
		if err != nil {
			log.Fatalf("server-pin: %v", err)
		}
		pin = p
	case *pinFile != "":
		// all channels use the same cert, any address works
		_, statErr := os.Stat(*pinFile)
		existed := statErr == nil
		p, err := transport.ResolvePin(srv.addr, srv.dc.ServerName, *pinFile)
		if err != nil {
			log.Fatalf("resolve server pin: %v", err)
		}
		pin = p
		if existed {
			log.Printf("verified server against saved pin in %s", *pinFile)
		} else {
			log.Printf("saved server certificate fingerprint to %s (%x)", *pinFile, pin)
		}
	}
	srv.dc.Pin = pin
	glueSrv.dc.Pin = pin

	if pin == nil && *insecure {
		log.Println("WARNING: insecure without server_pin/pin_file: any certificate is accepted, " +
			"a man in the middle can pretend to be the server. Set pin_file (see client-config.example.json)")
	}

	switch *mode {
	case "tun":
		err = runTunMode(srv, key, *tunName, *tunMTU, *tunPaths, *tunMeasure, *tunMeasureInterval)
	case "vpn":
		paths := *gamePaths
		if len(gameProcesses) > 0 && paths <= 0 {
			paths = 3
		}
		err = runVPNMode(srv, key, *vpnTunName, *vpnTunMTU, glueSrv, gameProcesses, paths, *vpnUpMbps)
	case "droptest":
		switch {
		case *dropCount > 0 && *dropPaths > 1:
			runDropMultipath(srv, key, *dropCount, *dropInterval, *dropPaths)
		case *dropCount > 0:
			runDropStress(srv, key, *dropCount, *dropInterval)
		default:
			runDropTest(srv, key)
		}
	default:
		err = runSocksMode(srv, *listenAddr, key)
	}
	if err != nil {
		log.Fatalf("%v", err)
	}
}
