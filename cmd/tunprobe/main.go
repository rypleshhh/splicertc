// Command tunprobe is a diagnostic tool: it creates a TUN interface,
// reads raw IP packets, classifies each as real traffic or local
// discovery noise (internal/pktfilter), and logs accordingly — real
// traffic gets a full line every time, noise just increments counters
// summarized periodically. No forwarding yet.
//
// The tun.Device interface (tailscale's wireguard-go fork) is identical
// across platforms: this code runs unmodified on Linux (/dev/net/tun)
// and Windows (wintun.dll) — only tun.CreateTUN's internals differ.
package main

import (
	"flag"
	"log"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/pktfilter"
)

func main() {
	name := flag.String("name", "dormtun0", "TUN interface name (Windows: display name; Linux: device name)")
	mtu := flag.Int("mtu", 1420, "MTU for the interface")
	flag.Parse()

	dev, err := tun.CreateTUN(*name, *mtu)
	if err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	defer dev.Close()

	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, *name, *mtu)
	log.Println("waiting for packets — on Linux, bring the interface up and route something through it in another shell; on Windows, do the same via netsh once the interface appears")

	noise := newNoiseCounter()
	go noise.summarizeEvery(5 * time.Second)

	batch := dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, *mtu+32)
	}
	sizes := make([]int, batch)

	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		for i := 0; i < n; i++ {
			info, ok := pktfilter.Parse(bufs[i][:sizes[i]])
			if !ok {
				log.Printf("unparseable packet, %d bytes", sizes[i])
				continue
			}
			if info.Noise {
				noise.record(info.Reason)
				continue
			}
			log.Println(info.String())
		}
	}
}

// noiseCounter tallies suppressed noise packets by reason and prints a
// summary on a fixed interval instead of one log line per packet —
// mDNS/SSDP/etc. fire constantly and would otherwise drown out the
// traffic we actually care about.
type noiseCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newNoiseCounter() *noiseCounter {
	return &noiseCounter{counts: make(map[string]int)}
}

func (n *noiseCounter) record(reason string) {
	n.mu.Lock()
	n.counts[reason]++
	n.mu.Unlock()
}

func (n *noiseCounter) summarizeEvery(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		n.mu.Lock()
		if len(n.counts) == 0 {
			n.mu.Unlock()
			continue
		}
		log.Printf("--- noise suppressed in the last %v ---", interval)
		total := 0
		for reason, count := range n.counts {
			log.Printf("  %s: %d", reason, count)
			total += count
		}
		log.Printf("  total: %d packets", total)
		n.counts = make(map[string]int)
		n.mu.Unlock()
	}
}
