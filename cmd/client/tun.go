package main

import (
	"log"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/glue"
	"tcp-dormtun/internal/measure"
	"tcp-dormtun/internal/pktfilter"
)

// runTunMode captures UDP from the TUN device, sends it through glue and
// writes the replies back into the TUN. IPv4 only.
func runTunMode(glueAddr string, insecure bool, pin []byte, tunName string, mtu int, paths int, doMeasure bool, measureInterval time.Duration, key []byte) {
	if paths < 1 {
		paths = 1
	}
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	defer dev.Close()
	actualName, _ := dev.Name()
	log.Printf("TUN interface up: %s (requested %q, mtu %d)", actualName, tunName, mtu)

	var stats *measure.Stats
	if doMeasure {
		stats = measure.New()
	}

	flows := newFlowTable()
	var onPing func(uint64)
	if stats != nil {
		onPing = stats.OnRecv
	}
	gp, err := startGluePaths(glueAddr, insecure, pin, key, paths, glueReplyHandler(flows, func(pkt []byte) {
		if _, err := dev.Write([][]byte{pkt}, 0); err != nil {
			log.Printf("TUN write: %v", err)
		}
	}, onPing))
	if err != nil {
		log.Fatalf("dial glue channel: %v", err)
	}
	log.Printf("connected to glue channel %s over %d path(s)", glueAddr, gp.live())

	go func() {
		for now := range time.Tick(2 * time.Second) {
			flows.sweep(now, gameFlowIdleTimeout)
		}
	}()

	log.Println("waiting for UDP packets, set up the interface and routes")

	var seq atomic.Uint32
	nextSeq := func() uint32 { return seq.Add(1) }
	writeAllPaths := gp.send

	if stats != nil {
		var nonce uint64
		// ping sender
		go func() {
			ticker := time.NewTicker(measureInterval)
			defer ticker.Stop()
			for range ticker.C {
				nonce++
				stats.OnSend(nonce)
				wire := frame.New(nextSeq(), glue.EncodePing(nonce)).Marshal()
				writeAllPaths(wire)
			}
		}()
		// periodic summary
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				log.Printf("[measure %d-path] %s", paths, stats.Snapshot(time.Second).String())
			}
		}()
		log.Printf("measurement enabled: pinging every %v across %d path(s)", measureInterval, paths)
	}

	batch := dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+32)
	}
	sizes := make([]int, batch)

	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			log.Fatalf("TUN read: %v", err)
		}
		for i := 0; i < n; i++ {
			info, ok := pktfilter.Parse(bufs[i][:sizes[i]])
			if !ok || info.Noise || info.Version != 4 || info.Proto != 17 || info.Payload == nil {
				continue
			}

			fi := flowInfo{origSrcPort: info.SrcPort, origDstPort: info.DstPort}
			copy(fi.origSrc[:], info.Src.To4())
			copy(fi.origDst[:], info.Dst.To4())

			flowID, ok := flows.id(fi, time.Now())
			if !ok {
				continue // all flow IDs in use
			}

			envelope := glue.EncodeOutbound(flowID, info.Dst, info.DstPort, info.Payload)
			wire := frame.New(nextSeq(), envelope).Marshal()
			writeAllPaths(wire)
		}
	}
}
