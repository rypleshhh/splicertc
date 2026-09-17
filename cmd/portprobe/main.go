// portprobe answers one question: which ports actually get through the
// network you're sitting in. The server binds a whole list of TCP and
// UDP ports at once and answers each with a token naming that exact
// port; the client tries them all and prints what came back.
//
// The token carries the port number on purpose. A plain timeout means
// "blocked"; a token for a *different* port (or garbage) means a
// middlebox answered or redirected instead of the real server — a very
// different finding, and one a simple connect-test would report as
// success.
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

// Defaults lean on ports a restrictive network plausibly allows:
// standard web/mail/VPN/STUN ports, plus the high ports this project
// already tried and saw blocked, as a control group.
const (
	defaultTCP = "80,443,8080,8443,2053,2083,2087,2096,53,123,143,465,587,993,995,1194,3478,5349,5222,3389"
	defaultUDP = "443,53,123,500,1194,3478,4500,51820,8443"
)

func token(port int, proto string) string {
	return fmt.Sprintf("PORTPROBE-OK %s/%d\n", proto, port)
}

// UDP source addresses are trivially spoofed, so a server that answers
// any datagram with a larger one is an amplification weapon: an
// attacker sends tiny packets with a victim's address and we blast the
// replies at the victim. Two rules make that worthless — the request
// must carry a magic prefix (no answering random scan traffic), and it
// must be at least as large as our reply (so the "amplification" factor
// is below 1 and there's nothing to gain). Anything else is dropped in
// silence.
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
	// "none" spelled out, because Windows PowerShell 5.1 silently drops
	// an empty-string argument to a native binary — `-udp ""` arrives as
	// a bare `-udp`, which then swallows the next flag as its value.
	if t := strings.TrimSpace(s); t == "" || t == "none" || t == "-" {
		return nil
	}
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := strconv.Atoi(f)
		if err != nil || p < 1 || p > 65535 {
			log.Fatalf("bad port %q", f)
		}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Well-known public endpoints, one per interesting port. Probing these
// says whether the network lets that port out at all, without opening
// a single hole in our own VPS firewall — useful for narrowing down
// which ports are even worth testing against our own box.
const defaultTargets = "www.google.com:80,www.google.com:443,github.com:22,8.8.8.8:53," +
	"smtp.gmail.com:25,smtp.gmail.com:465,smtp.gmail.com:587,imap.gmail.com:993," +
	"pop.gmail.com:995,ftp.gnu.org:21,irc.libera.chat:6667,irc.libera.chat:6697"

// probeTarget just asks whether a TCP connection to somebody else's
// server completes. No token to compare against — a completed handshake
// (and any banner the service volunteers) is the whole signal.
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
		// Plenty of services (HTTPS, HTTP) say nothing until spoken to;
		// the completed handshake already answered the question.
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
	fmt.Println("a port open here is worth re-testing against your own server — a filter can allow a port only toward well-known destinations")
}

func runServer(tcpPorts, udpPorts []int) {
	var bound, skipped []string

	for _, p := range tcpPorts {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			// Almost always "address already in use" — something real
			// is on that port (sshd, a web server, Xray). Skipping is
			// the right move: never fight a live service for its port.
			skipped = append(skipped, fmt.Sprintf("tcp/%d (%v)", p, err))
			continue
		}
		bound = append(bound, fmt.Sprintf("tcp/%d", p))
		go func(ln net.Listener, p int) {
			// Cap concurrent connections per port so a flood can't turn
			// this throwaway diagnostic into a memory-exhaustion lever
			// on a box that's running real services.
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
					// Then echo whatever arrives, so the client can hold
					// the connection open and find out whether the
					// network lets a long-lived flow survive — the
					// question that actually decides whether a tunnel
					// can live on this port.
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
					continue // not ours, or too short to answer safely
				}
				pc.WriteTo([]byte(token(p, "udp")), addr)
			}
		}(pc, p)
	}

	log.Printf("listening on %d ports: %s", len(bound), strings.Join(bound, " "))
	if len(skipped) > 0 {
		log.Printf("skipped %d ports already in use (expected — leave live services alone):", len(skipped))
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
	status string // "open", "blocked", or a description of what went wrong
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
		r.status = fmt.Sprintf("WRONG REPLY %q — something answered instead of our server", strings.TrimSpace(got))
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
	// UDP has no handshake: a lost probe is indistinguishable from a
	// blocked one, so retry before calling it blocked.
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
			r.status = fmt.Sprintf("WRONG REPLY %q — something answered instead of our server", strings.TrimSpace(got))
		}
		return r
	}
	r.status = "blocked (no reply after 3 tries)"
	return r
}

// sustain holds one port open and keeps traffic flowing on it, because
// "a connection can be established" and "a tunnel can live here for
// hours" are different questions — and this project has already been
// bitten by the second one (a flow that came up fine and died a minute
// and a half later).
func sustain(host string, r result, dur, interval time.Duration) string {
	addr := net.JoinHostPort(host, strconv.Itoa(r.port))
	conn, err := net.DialTimeout(r.proto, addr, 5*time.Second)
	if err != nil {
		return "died immediately: " + classify(err)
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	if r.proto == "tcp" {
		// Drain the greeting token before the echo phase.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return "died reading greeting: " + classify(err)
		}
	}

	start := time.Now()
	deadline := start.Add(dur)
	var sent, lost int
	// Magic-prefixed so the UDP side accepts it (see validUDPRequest);
	// harmless on TCP, which just echoes whatever it gets.
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
				// A lost datagram isn't a dead path; only a long run of
				// them is.
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
		fmt.Println("nothing got through — check that the server is running and the VPS firewall allows these ports before concluding the network blocks them")
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
	targets := flag.String("targets", "", "client mode: instead of probing our own server, TCP-connect to these host:port pairs (comma-separated, or \"default\" for a built-in list of public services) — needs no server and no firewall changes")
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
