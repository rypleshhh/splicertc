package main

import (
	"io"
	"log"
	"net"

	"github.com/xtaci/smux"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/proto"
	"tcp-dormtun/internal/socks5"
	"tcp-dormtun/internal/transport"
)

// socks5 mode: a local SOCKS5 proxy, every TCP connection becomes one
// smux stream inside a single TLS connection to the server.

func runSocksMode(serverAddr, listenAddr string, insecure bool, pin, key []byte) {
	conn, err := transport.Dial(serverAddr, transport.DialConfig{Insecure: insecure, Pin: pin})
	if err != nil {
		log.Fatalf("dial server: %v", err)
	}
	if key != nil {
		if err := auth.ClientHandshake(conn, key); err != nil {
			log.Fatalf("auth: %v", err)
		}
	}
	sess, err := smux.Client(conn, nil)
	if err != nil {
		log.Fatalf("smux client: %v", err)
	}
	log.Printf("connected to tunnel server %s", serverAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("socks5 listen: %v", err)
	}
	log.Printf("SOCKS5 proxy listening on %s", listenAddr)

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

	stream, err := sess.OpenStream()
	if err != nil {
		log.Printf("open stream: %v", err)
		socks5.WriteReply(appConn, proto.StatusFailure)
		return
	}
	defer stream.Close()

	if err := proto.WriteTarget(stream, target); err != nil {
		log.Printf("send target: %v", err)
		socks5.WriteReply(appConn, proto.StatusFailure)
		return
	}

	// the server answers with a SOCKS5 reply code
	status := make([]byte, 1)
	if _, err := io.ReadFull(stream, status); err != nil {
		socks5.WriteReply(appConn, proto.StatusFailure)
		return
	}
	if err := socks5.WriteReply(appConn, status[0]); err != nil || status[0] != proto.StatusOK {
		return
	}
	proto.Relay(appConn, stream)
}
