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

func parsePorts(s string) []int {
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
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					c.Write([]byte(token(p, "tcp")))
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
				_ = n
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
	// UDP has no handshake: a lost probe is indistinguishable from a
	// blocked one, so retry before calling it blocked.
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := conn.Write([]byte("probe")); err != nil {
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

func runClient(host string, tcpPorts, udpPorts []int, timeout time.Duration, parallel int) {
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
}

func main() {
	mode := flag.String("mode", "client", "server (run on the VPS) or client (run on the restricted network)")
	host := flag.String("host", "", "server address (client mode)")
	tcpList := flag.String("tcp", defaultTCP, "comma-separated TCP ports to probe")
	udpList := flag.String("udp", defaultUDP, "comma-separated UDP ports to probe")
	timeout := flag.Duration("timeout", 5*time.Second, "per-port timeout")
	parallel := flag.Int("parallel", 8, "how many ports to probe at once (client mode)")
	flag.Parse()

	tcpPorts := parsePorts(*tcpList)
	udpPorts := parsePorts(*udpList)

	switch *mode {
	case "server":
		runServer(tcpPorts, udpPorts)
	case "client":
		if *host == "" {
			log.Fatal("client mode needs -host <server ip>")
		}
		runClient(*host, tcpPorts, udpPorts, *timeout, *parallel)
	default:
		log.Fatalf("unknown -mode %q (want server or client)", *mode)
	}
}
