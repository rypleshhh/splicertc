package main

import (
	"flag"
	"fmt"
	"log"

	"tcp-dormtun/internal/transport"

	"github.com/xtaci/smux"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "server address")
	insecure := flag.Bool("insecure", false, "skip TLS cert verification (dev only)")
	flag.Parse()

	conn, err := transport.Dial(*addr, *insecure)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	log.Printf("connected to %s", *addr)

	sess, err := smux.Client(conn, nil)
	if err != nil {
		log.Fatalf("smux client: %v", err)
	}
	defer sess.Close()

	sendOnStream(sess, "first stream payload")
	sendOnStream(sess, "second stream payload")
}

func sendOnStream(sess *smux.Session, msg string) {
	stream, err := sess.OpenStream()
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	stream.Write([]byte(msg))
	buf := make([]byte, 128)
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("stream %d read: %v", stream.ID(), err)
		return
	}
	fmt.Printf("stream %d got back: %q\n", stream.ID(), buf[:n])
}
