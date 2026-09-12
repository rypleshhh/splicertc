package main

import (
	"flag"
	"io"
	"log"
	"net"

	"tcp-dormtun/internal/transport"

	"github.com/xtaci/smux"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	cert := flag.String("cert", "devcerts/dev.crt", "TLS cert file")
	key := flag.String("key", "devcerts/dev.key", "TLS key file")
	flag.Parse()

	ln, err := transport.Listen(*addr, *cert, *key)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("server listening on %s", *addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	log.Printf("client connected: %s", conn.RemoteAddr())

	sess, err := smux.Server(conn, nil)
	if err != nil {
		log.Printf("smux server: %v", err)
		return
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("session closed: %v", err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(s *smux.Stream) {
	defer s.Close()
	log.Printf("stream %d opened", s.ID())
	n, err := io.Copy(s, s)
	if err != nil && err != io.EOF {
		log.Printf("stream %d copy: %v", s.ID(), err)
	}
	log.Printf("stream %d closed, echoed %d bytes", s.ID(), n)
}
