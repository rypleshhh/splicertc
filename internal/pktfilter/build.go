package pktfilter

import (
	"encoding/binary"
	"sync/atomic"
)

var ipID uint32

// BuildIPv4UDP constructs a complete IPv4+UDP packet ready to write to a
// TUN device. The IPv4 header checksum is computed properly — an OS
// network stack will silently discard a packet with a bad one. The UDP
// checksum is left at 0 (explicitly allowed for IPv4 by RFC 768; it
// means "not computed", not "invalid") since we'd otherwise need the
// IPv4 pseudo-header too, for a field that changes nothing on Windows,
// Linux, or macOS as receivers here.
func BuildIPv4UDP(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45 // version 4, IHL 5 (20-byte header, no options)
	pkt[1] = 0    // DSCP/ECN, unused
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(atomic.AddUint32(&ipID, 1)))
	pkt[6] = 0x40 // flags: Don't Fragment; no offset
	pkt[7] = 0
	pkt[8] = 64 // TTL
	pkt[9] = 17 // protocol: UDP
	// pkt[10:12] header checksum — filled in below, after the rest of
	// the header is written (checksum is computed over the whole header
	// with this field itself treated as zero).
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[0:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	// udp[6:8] checksum left as 0 — see doc comment.
	copy(udp[8:], payload)

	return pkt
}

// ipv4HeaderChecksum is the standard one's-complement-of-the-sum
// algorithm (RFC 791), computed over the header with the checksum
// field itself treated as zero.
func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
