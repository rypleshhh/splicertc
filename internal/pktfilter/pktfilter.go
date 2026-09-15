// Package pktfilter inspects raw IP packets read off a TUN device and
// separates real traffic (unicast, going somewhere specific — what a
// game or any other application actually sends) from the local service
// discovery chatter every OS generates on any interface that has an
// address: NetBIOS, mDNS, SSDP, LLMNR, and the like. None of that has
// any business going through the tunnel.
//
// This is a negative list (known-noise ports + multicast/broadcast
// destinations), not a positive allowlist of "known game ports" —
// games routinely use dynamic/ephemeral UDP ports (Steam Datagram
// Relay in particular), so there's no fixed port to allow-list against.
package pktfilter

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Info describes one parsed packet.
type Info struct {
	Version          int
	Proto            byte
	Src, Dst         net.IP
	SrcPort, DstPort uint16 // 0 if not UDP, or ports weren't parseable
	Payload          []byte // UDP payload, if Proto==17 and long enough to have one; aliases the input slice
	Len              int
	Noise            bool
	Reason           string // why it's noise, or why it's not (both informative)
}

func (i Info) String() string {
	protoStr := protoName(i.Proto)
	portPart := ""
	if i.Proto == 17 && (i.SrcPort != 0 || i.DstPort != 0) {
		portPart = fmt.Sprintf(":%d", i.DstPort)
	}
	srcPortPart := ""
	if i.Proto == 17 && i.SrcPort != 0 {
		srcPortPart = fmt.Sprintf(":%d", i.SrcPort)
	}
	return fmt.Sprintf("IPv%d %s%s -> %s%s proto=%s len=%d noise=%v (%s)",
		i.Version, i.Src, srcPortPart, i.Dst, portPart, protoStr, i.Len, i.Noise, i.Reason)
}

// wellKnownNoisePorts are UDP ports used exclusively for local service
// discovery/announcement protocols — never for actual application data
// a game or a normal client would tunnel.
var wellKnownNoisePorts = map[uint16]string{
	137:  "NetBIOS Name Service",
	138:  "NetBIOS Datagram",
	139:  "NetBIOS Session",
	1900: "SSDP",
	5353: "mDNS",
	5355: "LLMNR",
	3702: "WS-Discovery",
	67:   "DHCP server",
	68:   "DHCP client",
}

// Parse reads the IP header (and UDP header, if present) from a raw
// packet as read off a TUN device (no link-layer header). ok is false
// if the packet is too short to even determine its IP version.
func Parse(pkt []byte) (info Info, ok bool) {
	if len(pkt) < 1 {
		return Info{}, false
	}
	info.Len = len(pkt)
	version := pkt[0] >> 4
	info.Version = int(version)

	switch version {
	case 4:
		if len(pkt) < 20 {
			return info, false
		}
		ihl := int(pkt[0]&0x0F) * 4
		info.Proto = pkt[9]
		info.Src = net.IP(pkt[12:16])
		info.Dst = net.IP(pkt[16:20])

		if info.Proto == 17 && len(pkt) >= ihl+4 {
			info.SrcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
			info.DstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
			if len(pkt) >= ihl+8 {
				info.Payload = pkt[ihl+8:]
			}
		}

	case 6:
		if len(pkt) < 40 {
			return info, false
		}
		info.Proto = pkt[6]
		info.Src = net.IP(pkt[8:24])
		info.Dst = net.IP(pkt[24:40])

		// Doesn't walk IPv6 extension header chains — fine here, real
		// traffic to a game server won't have them between the fixed
		// header and the UDP payload.
		if info.Proto == 17 && len(pkt) >= 44 {
			info.SrcPort = binary.BigEndian.Uint16(pkt[40:42])
			info.DstPort = binary.BigEndian.Uint16(pkt[42:44])
		}

	default:
		return info, false
	}

	info.Noise, info.Reason = classify(info)
	return info, true
}

func classify(i Info) (noise bool, reason string) {
	if i.Dst.IsMulticast() {
		return true, "multicast destination"
	}
	if i.Version == 4 {
		// ".255" only means "subnet broadcast" within a private/
		// link-local range — on the public internet it's an ordinary
		// host address. Full-tunnel VPN mode runs this classifier
		// against every internet-bound packet (not just a hand-picked
		// local subnet like the original glue/tun modes), so without
		// this scoping a real server whose public IP happens to end in
		// .255 would be silently dropped instead of tunneled.
		if d4 := i.Dst.To4(); d4 != nil && d4[3] == 255 && (i.Dst.IsPrivate() || i.Dst.IsLinkLocalUnicast()) {
			return true, "broadcast destination"
		}
	}
	if i.Proto == 17 {
		if name, known := wellKnownNoisePorts[i.DstPort]; known {
			return true, name
		}
	}
	return false, "unicast, not a known discovery port"
}

func protoName(p byte) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("proto-%d", p)
	}
}
