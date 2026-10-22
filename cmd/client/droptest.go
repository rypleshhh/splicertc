package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"time"

	"tcp-dormtun/internal/auth"
	"tcp-dormtun/internal/frame"
	"tcp-dormtun/internal/transport"
)

// droptest mode: sends numbered frames to the droppable channel to see
// how late/lost they get on the real network. Nothing is relayed.

// runDropTest sends a few frames with artificial delays. Delays over
// 150ms should show up as drops on the server.
func runDropTest(srv endpoint, key []byte) {
	conn, err := transport.Dial(srv.addr, srv.dc)
	if err != nil {
		log.Fatalf("dial droppable: %v", err)
	}
	defer conn.Close()
	if err := auth.ClientHandshake(conn, key); err != nil {
		log.Fatalf("auth: %v", err)
	}
	if err := sendNewSessionID(conn); err != nil {
		log.Fatalf("send session id: %v", err)
	}
	log.Printf("connected to droppable channel %s", srv.addr)

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

// runDropStress sends count frames every interval. Use with tc netem on
// the server and check the server log for drops.
func runDropStress(srv endpoint, key []byte, count int, interval time.Duration) {
	conn, err := transport.Dial(srv.addr, srv.dc)
	if err != nil {
		log.Fatalf("dial droppable: %v", err)
	}
	defer conn.Close()
	if err := auth.ClientHandshake(conn, key); err != nil {
		log.Fatalf("auth: %v", err)
	}
	if err := sendNewSessionID(conn); err != nil {
		log.Fatalf("send session id: %v", err)
	}
	log.Printf("connected to droppable channel %s, sending %d frames every %v", srv.addr, count, interval)

	sent := 0
	for i := 0; i < count; i++ {
		f := frame.New(uint32(i), []byte(fmt.Sprintf("frame #%d", i)))
		if _, err := conn.Write(f.Marshal()); err != nil {
			log.Printf("write frame %d: %v (stopping)", i, err)
			break
		}
		sent++
		time.Sleep(interval)
	}
	log.Printf("done: %d/%d frames written to the connection (check server log for accepted/DROPPED)", sent, count)
	time.Sleep(300 * time.Millisecond)
}

// sendNewSessionID writes a random 8 byte session ID.
func sendNewSessionID(conn net.Conn) error {
	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		return err
	}
	_, err := conn.Write(sid)
	return err
}

// runDropMultipath sends every frame over several connections with the
// same session ID. A frame is lost only if it's lost on all of them.
func runDropMultipath(srv endpoint, key []byte, count int, interval time.Duration, paths int) {
	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		log.Fatalf("generate session id: %v", err)
	}
	log.Printf("multipath droptest: session %x, %d paths, %d frames every %v", sid, paths, count, interval)

	conns := make([]net.Conn, paths)
	for i := 0; i < paths; i++ {
		conn, err := transport.Dial(srv.addr, srv.dc)
		if err != nil {
			log.Fatalf("dial path %d: %v", i, err)
		}
		if err := auth.ClientHandshake(conn, key); err != nil {
			log.Fatalf("auth on path %d: %v", i, err)
		}
		if _, err := conn.Write(sid); err != nil {
			log.Fatalf("send session id on path %d: %v", i, err)
		}
		conns[i] = conn
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < count; i++ {
		f := frame.New(uint32(i), []byte(fmt.Sprintf("frame #%d", i)))
		wire := f.Marshal()
		for pathIdx, c := range conns {
			if _, err := c.Write(wire); err != nil {
				log.Printf("frame %d: write failed on path %d: %v", i, pathIdx, err)
			}
		}
		time.Sleep(interval)
	}
	log.Printf("done: %d frames sent on all %d paths (check server log for the session summary)", count, paths)
	time.Sleep(300 * time.Millisecond)
}
