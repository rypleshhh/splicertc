package pktfilter

import (
	"encoding/binary"
	"sync/atomic"
)

var ipID uint32

// BuildIPv4UDP builds an IPv4+UDP packet to write into the TUN device.
// UDP checksum is 0, which is allowed for IPv4.
func BuildIPv4UDP(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45 // IPv4, 20 byte header
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(atomic.AddUint32(&ipID, 1)))
	pkt[6] = 0x40 // don't fragment
	pkt[7] = 0
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[0:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	return pkt
}

// RFC 791 header checksum.
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
