// Command tunprobe creates a TUN interface and logs the packets it sees.
// Noise (mDNS, SSDP...) is only counted. Doesn't forward anything.
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
	log.Println("waiting for packets, set up the interface and route something through it")

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

// noiseCounter counts noise packets and prints a summary from time to time.
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
