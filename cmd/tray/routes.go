package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
)

// The route script is built into tray.exe and passed to PowerShell on the
// command line. A copy on disk next to the (elevated) tray could be
// replaced by any program that can write to that folder.
//
//go:embed setup-vpn-route.ps1
var routeScript string

// Same defaults as client.exe when client-config.json doesn't set them.
const (
	defaultTunName   = "dormvpn0"
	defaultVPNSubnet = "10.66.0.0/24"
)

// tunConfig is what the route script needs to know about the TUN side.
type tunConfig struct {
	Name      string
	IP        netip.Addr // client, .2 of the subnet
	Gateway   netip.Addr // server end, .1
	PrefixLen int
}

// tunConfigFromJSON reads vpn_tun_name and vpn_subnet from client-config.json
// and computes the addresses the same way client.exe does.
func tunConfigFromJSON(data []byte) (tunConfig, error) {
	var cfg struct {
		TunName string `json:"vpn_tun_name"`
		Subnet  string `json:"vpn_subnet"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return tunConfig{}, err
	}
	if cfg.TunName == "" {
		cfg.TunName = defaultTunName
	}
	if cfg.Subnet == "" {
		cfg.Subnet = defaultVPNSubnet
	}
	p, err := netip.ParsePrefix(cfg.Subnet)
	if err != nil {
		return tunConfig{}, fmt.Errorf("vpn_subnet: %w", err)
	}
	if !p.Addr().Is4() || p.Bits() > 30 {
		return tunConfig{}, fmt.Errorf("vpn_subnet %s: нужна IPv4-подсеть /30 или больше", cfg.Subnet)
	}
	gw := p.Masked().Addr().Next()
	return tunConfig{Name: cfg.TunName, IP: gw.Next(), Gateway: gw, PrefixLen: p.Bits()}, nil
}

func loadTunConfig() (tunConfig, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return tunConfig{}, err
	}
	return tunConfigFromJSON(data)
}

// The marker client.exe logs after every (re)connect, followed by the
// IP:port it actually connected to.
const connectedMarker = "connected to vpn channel"

// serverIPFromLine takes the server IP from the client's "connected to vpn
// channel <IP>:<port>" line. The anti-loop route must be for exactly the
// address client.exe uses, so the tray doesn't resolve the name itself.
func serverIPFromLine(line string) (netip.Addr, error) {
	_, rest, ok := strings.Cut(line, connectedMarker)
	if !ok {
		return netip.Addr{}, fmt.Errorf("нет %q в строке", connectedMarker)
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return netip.Addr{}, fmt.Errorf("в строке клиента нет адреса сервера: %q", line)
	}
	host, _, err := net.SplitHostPort(fields[0])
	if err != nil {
		return netip.Addr{}, fmt.Errorf("адрес сервера %q: %w", fields[0], err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("адрес сервера %q не IP", host)
	}
	// the tunnel and the anti-loop route are IPv4 only, and global IPv6 is
	// blocked while the tunnel is up
	if !ip.Unmap().Is4() {
		return netip.Addr{}, fmt.Errorf("сервер подключён по IPv6 (%s), туннель работает только с IPv4", ip)
	}
	return ip.Unmap(), nil
}

// psSafe is what may go into a quoted script argument: IPs and adapter
// names. Anything else (quotes, $, backticks, unicode quotes PowerShell
// also accepts) is refused instead of escaped.
var psSafe = regexp.MustCompile(`^[A-Za-z0-9._ -]{1,64}$`)

func psQuote(s string) (string, error) {
	if !psSafe.MatchString(s) {
		return "", fmt.Errorf("недопустимое значение %q", s)
	}
	return "'" + s + "'", nil
}

// setupArgs are the script arguments for bringing the routes up.
func setupArgs(serverIP netip.Addr, tc tunConfig) ([]string, error) {
	args := []string{}
	for _, p := range []struct{ name, value string }{
		{"ServerIP", serverIP.String()},
		{"TunName", tc.Name},
		{"TunIP", tc.IP.String()},
		{"TunGateway", tc.Gateway.String()},
	} {
		q, err := psQuote(p.value)
		if err != nil {
			return nil, fmt.Errorf("-%s: %w", p.name, err)
		}
		args = append(args, "-"+p.name, q)
	}
	return append(args, "-TunPrefixLength", strconv.Itoa(tc.PrefixLen)), nil
}

// encodedCommand returns the -EncodedCommand value that runs script with
// args: base64 of UTF-16LE "& { script } args". With -EncodedCommand
// PowerShell 5.1 writes everything that isn't output to stderr as CLIXML,
// so all streams are merged into output, which stays plain text. The
// Net* cmdlets take $ProgressPreference from the global scope, so it's
// set out here.
func encodedCommand(script string, args []string) string {
	src := "$ProgressPreference = 'SilentlyContinue'\n& {\n" + script + "\n} " + strings.Join(args, " ") + " *>&1"
	u := utf16.Encode([]rune(src))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// powershellArgs is the argument list for powershell.exe.
func powershellArgs(args []string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodedCommand(routeScript, args)}
}

// runRouteScript runs the built-in route script and returns its output.
func runRouteScript(args []string) ([]byte, error) {
	rc := exec.Command(systemExe(`WindowsPowerShell\v1.0\powershell.exe`), powershellArgs(args)...)
	rc.Dir = exeDir
	rc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return rc.CombinedOutput()
}

// teardownRoutes removes what the route script added outside the TUN
// adapter (the IPv6 block). Routes on the TUN go away with the adapter.
func teardownRoutes() {
	out, err := runRouteScript([]string{"-Teardown"})
	logger.Printf("route script -Teardown: %s (err=%v)", strings.TrimSpace(string(out)), err)
}
