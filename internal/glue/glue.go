// Package glue defines the small envelope format that rides inside
// frame.Frame.Payload once real captured UDP traffic (not demo data)
// flows through the droppable channel. It's deliberately minimal: just
// enough to let the server dial the right destination and the client
// reconstruct a reply packet the OS will accept.
package glue

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	msgOutbound byte = 1 // client -> server: forward this payload to dst
	msgInbound  byte = 2 // server -> client: this payload came back from dst
)

// EncodeOutbound builds a client->server envelope. dst must be a 4-byte
// (IPv4) address — IPv6 game traffic isn't handled yet.
func EncodeOutbound(flowID uint16, dst net.IP, dstPort uint16, payload []byte) []byte {
	dst4 := dst.To4()
	buf := make([]byte, 1+2+4+2+len(payload))
	buf[0] = msgOutbound
	binary.BigEndian.PutUint16(buf[1:3], flowID)
	copy(buf[3:7], dst4)
	binary.BigEndian.PutUint16(buf[7:9], dstPort)
	copy(buf[9:], payload)
	return buf
}

// DecodeOutbound reverses EncodeOutbound. payload aliases the input slice.
func DecodeOutbound(b []byte) (flowID uint16, dst net.IP, dstPort uint16, payload []byte, err error) {
	if len(b) < 9 || b[0] != msgOutbound {
		return 0, nil, 0, nil, fmt.Errorf("not a valid outbound envelope (len=%d)", len(b))
	}
	flowID = binary.BigEndian.Uint16(b[1:3])
	dst = net.IP(append([]byte(nil), b[3:7]...)) // copy — b may be reused
	dstPort = binary.BigEndian.Uint16(b[7:9])
	payload = b[9:]
	return flowID, dst, dstPort, payload, nil
}

// EncodeInbound builds a server->client envelope.
func EncodeInbound(flowID uint16, payload []byte) []byte {
	buf := make([]byte, 1+2+len(payload))
	buf[0] = msgInbound
	binary.BigEndian.PutUint16(buf[1:3], flowID)
	copy(buf[3:], payload)
	return buf
}

// DecodeInbound reverses EncodeInbound. payload aliases the input slice.
func DecodeInbound(b []byte) (flowID uint16, payload []byte, err error) {
	if len(b) < 3 || b[0] != msgInbound {
		return 0, nil, fmt.Errorf("not a valid inbound envelope (len=%d)", len(b))
	}
	flowID = binary.BigEndian.Uint16(b[1:3])
	payload = b[3:]
	return flowID, payload, nil
}
