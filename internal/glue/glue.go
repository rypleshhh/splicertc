// Package glue is the envelope format for UDP packets inside a frame:
// where to send it (client->server) and which flow a reply belongs to
// (server->client).
package glue

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	msgOutbound byte = 1 // client -> server: forward this payload to dst
	msgInbound  byte = 2 // server -> client: this payload came back from dst
	msgPing     byte = 3 // ping, server sends it back
	// path ping: the server sends it back on the same connection only,
	// without seq dedup. Used to check each path separately.
	msgPathPing byte = 4
)

// Path setup, after auth. The client sends a hello (protocol version and
// session ID), the server answers with an accept: a status and the
// epoch of the server session the path joined. A new epoch means a new
// server session (server restart, or the old one expired) whose reply
// seq starts from zero again.
const (
	ProtocolVersion byte = 1
	SessionIDSize        = 8
	HelloSize            = 1 + SessionIDSize
	AcceptSize           = 1 + 8
)

// Accept statuses.
const (
	StatusOK          byte = 0
	StatusBusy        byte = 1 // a server or per-client limit is reached
	StatusRefused     byte = 2 // the session belongs to another client
	StatusUnsupported byte = 3 // unknown protocol version
)

// ErrUnsupportedVersion: client and server speak different glue
// versions, reconnecting won't help.
var ErrUnsupportedVersion = errors.New("glue protocol version not supported by the server (update the client and the server together)")

func EncodeHello(sid []byte) []byte {
	buf := make([]byte, HelloSize)
	buf[0] = ProtocolVersion
	copy(buf[1:], sid)
	return buf
}

// DecodeHello: sid points into b.
func DecodeHello(b []byte) (version byte, sid []byte) {
	return b[0], b[1:HelloSize]
}

func EncodeAccept(status byte, epoch uint64) []byte {
	buf := make([]byte, AcceptSize)
	buf[0] = status
	binary.BigEndian.PutUint64(buf[1:], epoch)
	return buf
}

// DecodeAccept returns the epoch, or an error for any status but OK.
func DecodeAccept(b []byte) (epoch uint64, err error) {
	switch b[0] {
	case StatusOK:
		return binary.BigEndian.Uint64(b[1:AcceptSize]), nil
	case StatusBusy:
		return 0, errors.New("server refused the path: session or path limit reached")
	case StatusRefused:
		return 0, errors.New("server refused the path: session belongs to another client")
	case StatusUnsupported:
		return 0, ErrUnsupportedVersion
	default:
		return 0, fmt.Errorf("server refused the path: unknown status %d", b[0])
	}
}

// EncodePathPing makes a path ping. The nonce is usually a send time.
func EncodePathPing(nonce uint64) []byte {
	buf := make([]byte, 1+8)
	buf[0] = msgPathPing
	binary.BigEndian.PutUint64(buf[1:9], nonce)
	return buf
}

func DecodePathPing(b []byte) (nonce uint64, ok bool) {
	if len(b) < 9 || b[0] != msgPathPing {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[1:9]), true
}

func IsPathPing(b []byte) bool {
	return len(b) >= 1 && b[0] == msgPathPing
}

// EncodePing makes a ping with a nonce, the server echoes it back.
func EncodePing(nonce uint64) []byte {
	buf := make([]byte, 1+8)
	buf[0] = msgPing
	binary.BigEndian.PutUint64(buf[1:9], nonce)
	return buf
}

func DecodePing(b []byte) (nonce uint64, ok bool) {
	if len(b) < 9 || b[0] != msgPing {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[1:9]), true
}

func IsPing(b []byte) bool {
	return len(b) >= 1 && b[0] == msgPing
}

// EncodeOutbound builds a client->server envelope. The format has room
// for an IPv4 address only.
func EncodeOutbound(flowID uint16, dst net.IP, dstPort uint16, payload []byte) ([]byte, error) {
	dst4 := dst.To4()
	if dst4 == nil {
		return nil, fmt.Errorf("glue: %s is not an IPv4 address", dst)
	}
	buf := make([]byte, 1+2+4+2+len(payload))
	buf[0] = msgOutbound
	binary.BigEndian.PutUint16(buf[1:3], flowID)
	copy(buf[3:7], dst4)
	binary.BigEndian.PutUint16(buf[7:9], dstPort)
	copy(buf[9:], payload)
	return buf, nil
}

// payload points into b.
func DecodeOutbound(b []byte) (flowID uint16, dst net.IP, dstPort uint16, payload []byte, err error) {
	if len(b) < 9 || b[0] != msgOutbound {
		return 0, nil, 0, nil, fmt.Errorf("not a valid outbound envelope (len=%d)", len(b))
	}
	flowID = binary.BigEndian.Uint16(b[1:3])
	dst = net.IP(append([]byte(nil), b[3:7]...)) // copy, b can be reused
	dstPort = binary.BigEndian.Uint16(b[7:9])
	payload = b[9:]
	return flowID, dst, dstPort, payload, nil
}

// MaxInboundPayload is the biggest UDP reply that fits into one frame
// together with the inbound header (type + flow ID).
const MaxInboundPayload = 65535 - 3

func EncodeInbound(flowID uint16, payload []byte) []byte {
	buf := make([]byte, 1+2+len(payload))
	buf[0] = msgInbound
	binary.BigEndian.PutUint16(buf[1:3], flowID)
	copy(buf[3:], payload)
	return buf
}

// payload points into b.
func DecodeInbound(b []byte) (flowID uint16, payload []byte, err error) {
	if len(b) < 3 || b[0] != msgInbound {
		return 0, nil, fmt.Errorf("not a valid inbound envelope (len=%d)", len(b))
	}
	flowID = binary.BigEndian.Uint16(b[1:3])
	payload = b[3:]
	return flowID, payload, nil
}

// Ports used for UDP amplification attacks. Games don't use them, so we
// never relay there.
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

// DestinationAllowed rejects loopback, link-local, multicast and the
// blocked ports above.
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
