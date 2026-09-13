package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/socks5"
	"tcp-dormtun/internal/transport"
)

func main() {
	mode := flag.String("mode", "socks5", "socks5 (default) or droptest")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	serverAddr := flag.String("server", "127.0.0.1:8443", "tunnel server address")
	dropAddr := flag.String("drop-addr", "127.0.0.1:8444", "droppable channel address (droptest mode)")
	insecure := flag.Bool("insecure", false, "skip TLS cert verification (dev only)")
	flag.Parse()

	if *mode == "droptest" {
		runDropTest(*dropAddr, *insecure)
		return
	}

	conn, err := transport.Dial(*serverAddr, *insecure)
	if err != nil {
		log.Fatalf("dial server: %v", err)
	}
	sess, err := smux.Client(conn, nil)
	if err != nil {
		log.Fatalf("smux client: %v", err)
	}
	log.Printf("connected to tunnel server %s", *serverAddr)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("socks5 listen: %v", err)
	}
	log.Printf("SOCKS5 proxy listening on %s", *listenAddr)

	for {
		appConn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleApp(appConn, sess)
	}
}

func handleApp(appConn net.Conn, sess *smux.Session) {
	defer appConn.Close()

	if err := socks5.Handshake(appConn); err != nil {
		log.Printf("socks5 handshake: %v", err)
		return
	}
	target, err := socks5.ReadRequest(appConn)
	if err != nil {
		log.Printf("socks5 request: %v", err)
		return
	}
	log.Printf("app requested %s", target)

	stream, err := sess.OpenStream()
	if err != nil {
		log.Printf("open stream: %v", err)
		socks5.WriteReply(appConn, false)
		return
	}
	defer stream.Close()

	if err := proto.WriteTarget(stream, target); err != nil {
		log.Printf("send target: %v", err)
		socks5.WriteReply(appConn, false)
		return
	}

	status := make([]byte, 1)
	if _, err := io.ReadFull(stream, status); err != nil || status[0] != 0 {
		log.Printf("server could not reach %s: %v", target, err)
		socks5.WriteReply(appConn, false)
		return
	}

	if err := socks5.WriteReply(appConn, true); err != nil {
		log.Printf("socks5 reply: %v", err)
		return
	}

	relay(appConn, stream)
	log.Printf("%s: closed", target)
}

func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// runDropTest sends a fixed sequence of frames over the droppable channel,
// injecting an artificial delay before some of them are written — standing
// in for "this frame got stuck behind a retransmit" without needing real
// packet loss. The server's TTL is 150ms (see cmd/server), so delays past
// that should show up there as drops.
func runDropTest(dropAddr string, insecure bool) {
	conn, err := transport.Dial(dropAddr, insecure)
	if err != nil {
		log.Fatalf("dial droppable: %v", err)
	}
	defer conn.Close()
	log.Printf("connected to droppable channel %s", dropAddr)

	delays := []time.Duration{0, 0, 300 * time.Millisecond, 0, 400 * time.Millisecond, 0}
	for i, d := range delays {
		f := frame.New(uint32(i), []byte(fmt.Sprintf("frame #%d", i)))
		if d > 0 {
			log.Printf("frame %d: simulating %v delay before send", i, d)
			time.Sleep(d)
		}
		if _, err := conn.Write(f.Marshal()); err != nil {
			log.Printf("write frame %d: %v", i, err)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.Println("all frames sent")
	time.Sleep(300 * time.Millisecond)
}
