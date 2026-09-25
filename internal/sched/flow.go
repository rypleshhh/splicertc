// Package sched keeps queueing delay out of the tunnel: a flow-fair,
// self-policing packet scheduler (FQ-CoDel, RFC 8290 + RFC 8289) for the
// single TCP stream the vpn channel multiplexes everything onto, an
// optional rate shaper for keeping that stream below the real link's
// capacity, and a non-blocking per-path writer for multipath.
//
// The problem all three address is the same one: this tunnel carries
// many independent flows (a game, a voice call, a download, DNS) inside
// one outer TCP connection, and a TCP connection is a single FIFO. Left
// alone, a bulk download fills the socket's send buffer and whatever
// bottleneck buffer sits on the path with megabytes of data, and every
// latency-sensitive packet written after that waits behind all of it.
package sched

import "encoding/binary"

// FlowKey identifies one transport-level flow in an IPv4 packet — the
// unit fair queueing isolates from every other flow.
type FlowKey struct {
	Proto            byte
	Src, Dst         [4]byte
	SrcPort, DstPort uint16
}

// FlowOf extracts pkt's flow key. Ports are only read for TCP/UDP
// packets that aren't IP fragments — every fragment of a datagram
// (first or not) gets the same port-less key, so the pieces of one
// datagram never land in two different flow queues. Anything that isn't
// a parseable IPv4 packet maps to the zero key, one shared catch-all
// flow.
func FlowOf(pkt []byte) FlowKey {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return FlowKey{}
	}
	var k FlowKey
	k.Proto = pkt[9]
	copy(k.Src[:], pkt[12:16])
	copy(k.Dst[:], pkt[16:20])

	fragmented := binary.BigEndian.Uint16(pkt[6:8])&0x3FFF != 0 // MF flag or non-zero fragment offset
	ihl := int(pkt[0]&0x0F) * 4
	if !fragmented && (k.Proto == 6 || k.Proto == 17) && ihl >= 20 && len(pkt) >= ihl+4 {
		k.SrcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		k.DstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}
	return k
}
