// portprobe checks which ports get through the network. The server
// listens on many TCP/UDP ports and answers with a token containing the
// port number, the client tries them all. A wrong token means something
// in the middle answered instead of our server.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// common web/mail/VPN ports plus some high ports that were blocked before
const (
	defaultTCP = "80,443,8080,8443,2053,2083,2087,2096,53,123,143,465,587,993,995,1194,3478,5349,5222,3389"
	defaultUDP = "443,53,123,500,1194,3478,4500,51820,8443"
)

func token(port int, proto string) string {
	return fmt.Sprintf("PORTPROBE-OK %s/%d\n", proto, port)
}

// To not be usable for UDP amplification, we only answer requests with
// the magic prefix that are at least as big as our reply.
const (
	probeMagic      = "PORTPROBE-REQ"
	probeRequestLen = 64
)

func validUDPRequest(b []byte) bool {
	return len(b) >= probeRequestLen && strings.HasPrefix(string(b), probeMagic)
}

func udpRequest() []byte {
	buf := make([]byte, probeRequestLen)
	copy(buf, probeMagic)
	return buf
}

func parsePorts(s string) []int {
	// "none" because PowerShell 5.1 drops empty string args
	if t := strings.TrimSpace(s); t == "" || t == "none" || t == "-" {
		return nil
	}
	seen := make(map[int]bool)
	var out []int
	add := func(p int) {
		if p < 1 || p > 65535 {
			log.Fatalf("bad port %d (must be 1-65535)", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		// range like "1-999"
		if dash := strings.IndexByte(f, '-'); dash > 0 {
			loStr, hiStr := f[:dash], f[dash+1:]
			lo, errLo := strconv.Atoi(loStr)
			hi, errHi := strconv.Atoi(hiStr)
			if errLo != nil || errHi != nil || lo > hi {
				log.Fatalf("bad port range %q", f)
			}
			for p := lo; p <= hi; p++ {
				add(p)
			}
			continue
		}
		p, err := strconv.Atoi(f)
		if err != nil {
			log.Fatalf("bad port %q", f)
		}
		add(p)
	}
	sort.Ints(out)
	return out
}

// Public servers on different ports, to test without our own server.
const defaultTargets = "www.google.com:80,www.google.com:443,github.com:22,8.8.8.8:53," +
	"smtp.gmail.com:25,smtp.gmail.com:465,smtp.gmail.com:587,imap.gmail.com:993," +
	"pop.gmail.com:995,ftp.gnu.org:21,irc.libera.chat:6667,irc.libera.chat:6697"

// probeTarget only checks that the TCP connection works.
func probeTarget(target string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return classify(err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 96)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		// HTTP/HTTPS don't send anything first, that's fine
		return "reachable"
	}
	banner := strings.TrimSpace(string(buf[:n]))
	if len(banner) > 40 {
		banner = banner[:40] + "..."
	}
	return fmt.Sprintf("reachable (%s)", banner)
}

func runTargets(targets []string, timeout time.Duration, parallel int) {
	type tres struct {
		target string
		status string
	}
	var (
		mu  sync.Mutex
		out []tres
		wg  sync.WaitGroup
		sem = make(chan struct{}, parallel)
	)
	for _, t := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s := probeTarget(t, timeout)
			mu.Lock()
			out = append(out, tres{t, s})
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].target < out[j].target })

	fmt.Printf("\nprobing public endpoints (no changes to your own server needed)\n\n")
	var ok []string
	for _, r := range out {
		mark := " "
		if strings.HasPrefix(r.status, "reachable") {
			mark = "+"
			ok = append(ok, r.target)
		}
		fmt.Printf(" %s %-24s %s\n", mark, r.target, r.status)
	}
	fmt.Printf("\n%d of %d reachable: %s\n", len(ok), len(out), strings.Join(ok, " "))
	fmt.Println("open ports should be tested against your own server too")
}

func runServer(tcpPorts, udpPorts []int) {
	var bound, skipped []string

	for _, p := range tcpPorts {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			// port is used by something else (sshd, xray...), skip it
			skipped = append(skipped, fmt.Sprintf("tcp/%d (%v)", p, err))
			continue
		}
		bound = append(bound, fmt.Sprintf("tcp/%d", p))
		go func(ln net.Listener, p int) {
			// limit connections per port
			sem := make(chan struct{}, 32)
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				select {
				case sem <- struct{}{}:
				default:
					conn.Close()
					continue
				}
				go func(c net.Conn) {
					defer func() { <-sem }()
					defer c.Close()
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, err := c.Write([]byte(token(p, "tcp"))); err != nil {
						return
					}
					// echo for the -sustain test
					buf := make([]byte, 4096)
					for {
						c.SetReadDeadline(time.Now().Add(2 * time.Minute))
						n, err := c.Read(buf)
						if err != nil {
							return
						}
						c.SetWriteDeadline(time.Now().Add(10 * time.Second))
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
					}
				}(conn)
			}
		}(ln, p)
	}

	for _, p := range udpPorts {
		pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("udp/%d (%v)", p, err))
			continue
		}
		bound = append(bound, fmt.Sprintf("udp/%d", p))
		go func(pc net.PacketConn, p int) {
			buf := make([]byte, 1024)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if !validUDPRequest(buf[:n]) {
					continue
				}
				pc.WriteTo([]byte(token(p, "udp")), addr)
			}
		}(pc, p)
	}

	log.Printf("listening on %d ports: %s", len(bound), strings.Join(bound, " "))
	if len(skipped) > 0 {
		log.Printf("skipped %d ports already in use:", len(skipped))
		for _, s := range skipped {
			log.Printf("  %s", s)
		}
	}
	log.Println("open these ports in the VPS firewall too, or you'll be measuring your own firewall instead of the network you're testing")
	select {}
}

type result struct {
	proto  string
	port   int
	status string // open, blocked or an error
}

func probeTCP(host string, port int, timeout time.Duration) result {
	r := result{proto: "tcp", port: port}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		r.status = classify(err)
		return r
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		r.status = "connected, no reply (" + classify(err) + ")"
		return r
	}
	got := string(buf[:n])
	if got == token(port, "tcp") {
		r.status = "open"
	} else {
		r.status = fmt.Sprintf("WRONG REPLY %q (not our server)", strings.TrimSpace(got))
	}
	return r
}

func probeUDP(host string, port int, timeout time.Duration) result {
	r := result{proto: "udp", port: port}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		r.status = classify(err)
		return r
	}
	defer conn.Close()

	buf := make([]byte, 128)
	req := udpRequest()
	// UDP can get lost, retry a few times
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := conn.Write(req); err != nil {
			r.status = classify(err)
			return r
		}
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		got := string(buf[:n])
		if got == token(port, "udp") {
			r.status = "open"
		} else {
			r.status = fmt.Sprintf("WRONG REPLY %q (not our server)", strings.TrimSpace(got))
		}
		return r
	}
	r.status = "blocked (no reply after 3 tries)"
	return r
}

// sustain keeps a connection open with traffic, to see if the network
// kills it after some time.
func sustain(host string, r result, dur, interval time.Duration) string {
	addr := net.JoinHostPort(host, strconv.Itoa(r.port))
	conn, err := net.DialTimeout(r.proto, addr, 5*time.Second)
	if err != nil {
		return "died immediately: " + classify(err)
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	if r.proto == "tcp" {
		// read the token first
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return "died reading greeting: " + classify(err)
		}
	}

	start := time.Now()
	deadline := start.Add(dur)
	var sent, lost int
	// needs the magic prefix for UDP
	payload := make([]byte, 256)
	copy(payload, probeMagic)

	for time.Now().Before(deadline) {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			return fmt.Sprintf("DIED after %v (%d msgs): %s", time.Since(start).Round(time.Second), sent, classify(err))
		}
		sent++

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			if r.proto == "udp" {
				// a few lost packets are ok
				lost++
				if lost > 10 {
					return fmt.Sprintf("DIED after %v (%d msgs, 10 replies missed in a row)", time.Since(start).Round(time.Second), sent)
				}
			} else {
				return fmt.Sprintf("DIED after %v (%d msgs): %s", time.Since(start).Round(time.Second), sent, classify(err))
			}
		} else {
			lost = 0
		}
		time.Sleep(interval)
	}
	return fmt.Sprintf("survived %v (%d msgs)", dur, sent)
}

func classify(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "blocked (timeout)"
	case strings.Contains(s, "refused"):
		return "refused (reached the host, nothing listening)"
	case strings.Contains(s, "reset"):
		return "reset (something actively killed it)"
	default:
		return s
	}
}

func runClient(host string, tcpPorts, udpPorts []int, timeout time.Duration, parallel int) []result {
	var (
		mu      sync.Mutex
		results []result
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, parallel)

	add := func(r result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	for _, p := range tcpPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			add(probeTCP(host, p, timeout))
		}(p)
	}
	for _, p := range udpPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			add(probeUDP(host, p, timeout))
		}(p)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].proto != results[j].proto {
			return results[i].proto < results[j].proto
		}
		return results[i].port < results[j].port
	})

	var open []string
	fmt.Printf("\nprobing %s (timeout %v)\n\n", host, timeout)
	for _, r := range results {
		mark := " "
		if r.status == "open" {
			mark = "+"
			open = append(open, fmt.Sprintf("%s/%d", r.proto, r.port))
		} else if strings.HasPrefix(r.status, "WRONG REPLY") {
			mark = "!"
		}
		fmt.Printf(" %s %-4s %-6d %s\n", mark, r.proto, r.port, r.status)
	}

	fmt.Printf("\n%d of %d got through: %s\n", len(open), len(results), strings.Join(open, " "))
	if len(open) == 0 {
		fmt.Println("nothing got through, check that the server is running and the firewall is open")
	}
	return results
}

func runSustain(host string, results []result, dur, interval time.Duration) {
	var openOnes []result
	for _, r := range results {
		if r.status == "open" {
			openOnes = append(openOnes, r)
		}
	}
	if len(openOnes) == 0 {
		return
	}

	fmt.Printf("\nholding %d open port(s) for %v to see which survive a long-lived flow\n\n", len(openOnes), dur)
	var wg sync.WaitGroup
	var mu sync.Mutex
	lines := make(map[string]string)

	for _, r := range openOnes {
		wg.Add(1)
		go func(r result) {
			defer wg.Done()
			verdict := sustain(host, r, dur, interval)
			mu.Lock()
			lines[fmt.Sprintf("%s/%d", r.proto, r.port)] = verdict
			mu.Unlock()
		}(r)
	}
	wg.Wait()

	keys := make([]string, 0, len(lines))
	for k := range lines {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-10s %s\n", k, lines[k])
	}
}

func main() {
	mode := flag.String("mode", "client", "server (run on the VPS) or client (run on the restricted network)")
	host := flag.String("host", "", "server address (client mode)")
	tcpList := flag.String("tcp", defaultTCP, "comma-separated TCP ports to probe")
	udpList := flag.String("udp", defaultUDP, "comma-separated UDP ports to probe")
	timeout := flag.Duration("timeout", 5*time.Second, "per-port timeout")
	parallel := flag.Int("parallel", 8, "how many ports to probe at once (client mode)")
	sustainFor := flag.Duration("sustain", 0, "client mode: after scanning, hold every open port this long with traffic flowing, to see which survive a long-lived flow (e.g. 5m)")
	sustainEvery := flag.Duration("sustain-interval", time.Second, "client mode: spacing between messages while sustaining")
	targets := flag.String("targets", "", "client mode: instead of probing our own server, TCP-connect to these host:port pairs (comma-separated, or \"default\" for a built-in list)")
	flag.Parse()

	if *targets != "" {
		list := *targets
		if list == "default" {
			list = defaultTargets
		}
		runTargets(strings.Split(list, ","), *timeout, *parallel)
		return
	}

	tcpPorts := parsePorts(*tcpList)
	udpPorts := parsePorts(*udpList)

	switch *mode {
	case "server":
		runServer(tcpPorts, udpPorts)
	case "client":
		if *host == "" {
			log.Fatal("client mode needs -host <server ip>")
		}
		results := runClient(*host, tcpPorts, udpPorts, *timeout, *parallel)
		if *sustainFor > 0 {
			runSustain(*host, results, *sustainFor, *sustainEvery)
		}
	default:
		log.Fatalf("unknown -mode %q (want server or client)", *mode)
	}
}
