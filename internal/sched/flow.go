// Package sched contains the packet queueing used by the tunnel:
// an FQ-CoDel scheduler, a token bucket shaper and a non-blocking
// writer for multipath connections.
package sched

import "encoding/binary"

// FlowKey identifies a flow by its IPv4 5-tuple.
type FlowKey struct {
	Proto            byte
	Src, Dst         [4]byte
	SrcPort, DstPort uint16
}

// FlowOf returns the flow key of an IPv4 packet. Fragments get no
// ports so all pieces of one datagram end up in the same queue.
// Non-IPv4 packets return the zero key.
func FlowOf(pkt []byte) FlowKey {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return FlowKey{}
	}
	var k FlowKey
	k.Proto = pkt[9]
	copy(k.Src[:], pkt[12:16])
	copy(k.Dst[:], pkt[16:20])

	fragmented := binary.BigEndian.Uint16(pkt[6:8])&0x3FFF != 0 // MF flag or fragment offset
	ihl := int(pkt[0]&0x0F) * 4
	if !fragmented && (k.Proto == 6 || k.Proto == 17) && ihl >= 20 && len(pkt) >= ihl+4 {
		k.SrcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		k.DstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}
	return k
}
