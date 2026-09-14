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
	msgPing     byte = 3 // client -> server -> client: measurement echo, carries a nonce
)

// EncodePing builds a client->server measurement ping carrying an opaque
// nonce the client uses to match the echo back to its send time. The
// server just echoes it back unchanged (as a ping), never touching UDP.
func EncodePing(nonce uint64) []byte {
	buf := make([]byte, 1+8)
	buf[0] = msgPing
	binary.BigEndian.PutUint64(buf[1:9], nonce)
	return buf
}

// DecodePing returns the nonce if b is a ping envelope, ok=false otherwise.
func DecodePing(b []byte) (nonce uint64, ok bool) {
	if len(b) < 9 || b[0] != msgPing {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[1:9]), true
}

// IsPing reports whether an envelope is a measurement ping (so the
// server can echo it without trying to decode it as UDP-carrying).
func IsPing(b []byte) bool {
	return len(b) >= 1 && b[0] == msgPing
}

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

// blockedPorts are classic UDP amplification-vector services (DNS, NTP,
// memcached, SSDP, etc.) — no legitimate game traffic targets these,
// and relaying to them on request is exactly how an open UDP relay
// becomes a DDoS amplifier: the attacker asks you to send a small
// request to one of these with the *victim's* address spoofed as the
// source, and a much larger reply lands on the victim instead.
//
// Note: our relay isn't directly spoofable this way today (net.DialUDP
// makes the reply come back to us, not to a third party) — this is
// defense in depth against that assumption ever changing, and against
// these ports being misused for other reasons.
var blockedPorts = map[uint16]string{
	17:    "QOTD",
	19:    "Chargen",
	53:    "DNS",
	111:   "RPC portmapper",
	123:   "NTP",
	137:   "NetBIOS",
	161:   "SNMP",
	389:   "LDAP",
	1900:  "SSDP",
	11211: "memcached",
}

// DestinationAllowed reports whether the glue channel should be allowed
// to relay UDP to dst:port. Rejects loopback, link-local, and multicast
// destinations (no legitimate reason a game client tunnels to any of
// those through a remote relay) and the amplification-vector ports
// above, regardless of destination.
func DestinationAllowed(dst net.IP, port uint16) (bool, string) {
	if dst.IsLoopback() {
		return false, "loopback destination"
	}
	if dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast() {
		return false, "link-local destination"
	}
	if dst.IsMulticast() {
		return false, "multicast destination"
	}
	if name, blocked := blockedPorts[port]; blocked {
		return false, fmt.Sprintf("blocked port (%s)", name)
	}
	return true, ""
}
