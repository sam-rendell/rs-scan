package sender

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/afpacket"
)

// Packet layout byte offsets for Ethernet + IPv4 + TCP/UDP.
const (
	ethLen = 14
	ipOff  = ethLen     // 14
	ipLen  = 20
	tcpOff = ipOff + ipLen // 34

	// IPv4 field offsets (absolute from packet start)
	offIPTotalLen = ipOff + 2  // 16
	offIPId       = ipOff + 4  // 18
	offIPChecksum = ipOff + 10 // 24
	offIPSrcIP    = ipOff + 12 // 26
	offIPDstIP    = ipOff + 16 // 30

	// TCP field offsets (absolute from packet start)
	offTCPSrcPort  = tcpOff + 0  // 34
	offTCPDstPort  = tcpOff + 2  // 36
	offTCPSeq      = tcpOff + 4  // 38
	offTCPAck      = tcpOff + 8  // 42
	offTCPDataOff  = tcpOff + 12 // 46
	offTCPFlags    = tcpOff + 13 // 47
	offTCPWindow   = tcpOff + 14 // 48
	offTCPChecksum = tcpOff + 16 // 50

	// SYN: 20-byte TCP header + 20-byte options (MSS+SACK+TS+NOP+WS) = 40 bytes
	synTCPLen = 40
	synPktLen = ethLen + ipLen + synTCPLen // 74

	// ACK: 20-byte TCP header, no options
	ackTCPLen = 20
	ackPktLen = ethLen + ipLen + ackTCPLen // 54

	// UDP field offsets (absolute from packet start)
	udpOff         = ipOff + ipLen // 34 (same position as TCP)
	udpHdrLen      = 8
	udpBasePktLen  = ethLen + ipLen + udpHdrLen // 42 (no payload)
	offUDPSrcPort  = udpOff + 0  // 34
	offUDPDstPort  = udpOff + 2  // 36
	offUDPLength   = udpOff + 4  // 38
	offUDPChecksum = udpOff + 6  // 40
)

// maxPayloadPkt is the max packet size for SendData/SendUDP scratch buffer.
// Eth(14) + IP(20) + TCP/UDP(20) + payload(≤1460) = 1514 (standard MTU frame).
const maxPayloadPkt = 1514

// RingSender handles high-speed packet injection using AF_PACKET TX_RING.
// Packets are built by patching a pre-built template — zero allocations per packet.
type RingSender struct {
	handle       *afpacket.TPacket
	synPkt       [synPktLen]byte
	ackPkt       [ackPktLen]byte
	udpPkt       [udpBasePktLen]byte         // base UDP template (no payload)
	scratch      [maxPayloadPkt]byte         // reusable buffer for SendData/SendUDP
	cookieSecret uint64
	ipID         uint16
}

// NewRingSender initializes a memory-mapped ring buffer for sending.
func NewRingSender(iface string, srcMAC, dstMAC net.HardwareAddr, srcIP net.IP) (*RingSender, error) {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(2048),
		afpacket.OptBlockSize(1024*1024), // 1MB per block
		afpacket.OptNumBlocks(64),        // 64MB total TX ring
		afpacket.OptPollTimeout(1*time.Millisecond),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_PACKET handle: %w", err)
	}

	// Random secret and starting IP.Id
	b := make([]byte, 16)
	rand.Read(b)
	secret := binary.LittleEndian.Uint64(b[0:8])
	ipID := binary.LittleEndian.Uint16(b[8:10])

	s := &RingSender{
		handle:       handle,
		cookieSecret: secret,
		ipID:         ipID,
	}

	srcIP4 := srcIP.To4()

	// Build SYN template (static fields only — mutable fields patched per-packet)
	// Options mimic a standard Linux 5.x stack so remote hosts negotiate full
	// option sets in their SYN-ACK, enabling passive OS fingerprinting.
	buildEthHeader(s.synPkt[:], srcMAC, dstMAC)
	buildIPv4Header(s.synPkt[:], srcIP4, synTCPLen)
	s.synPkt[offTCPDataOff] = 0xA0 // Data Offset = 10 words (40 bytes)
	s.synPkt[offTCPFlags] = 0x02   // SYN
	binary.BigEndian.PutUint16(s.synPkt[offTCPWindow:], 64240)
	o := tcpOff + 20 // start of TCP options
	// MSS (Kind=2, Len=4, Value=1460)
	s.synPkt[o+0] = 2
	s.synPkt[o+1] = 4
	s.synPkt[o+2] = 0x05
	s.synPkt[o+3] = 0xB4
	// SACK Permitted (Kind=4, Len=2)
	s.synPkt[o+4] = 4
	s.synPkt[o+5] = 2
	// Timestamps (Kind=8, Len=10, TSval=seed, TSecr=0)
	s.synPkt[o+6] = 8
	s.synPkt[o+7] = 10
	binary.BigEndian.PutUint32(s.synPkt[o+8:], uint32(secret)) // TSval from random seed
	// TSecr bytes [o+12..o+15] already zero
	// NOP (Kind=1)
	s.synPkt[o+16] = 1
	// Window Scale (Kind=3, Len=3, Value=7)
	s.synPkt[o+17] = 3
	s.synPkt[o+18] = 3
	s.synPkt[o+19] = 7

	// Build ACK template
	buildEthHeader(s.ackPkt[:], srcMAC, dstMAC)
	buildIPv4Header(s.ackPkt[:], srcIP4, ackTCPLen)
	s.ackPkt[offTCPDataOff] = 0x50 // Data Offset = 5 words (20 bytes)
	s.ackPkt[offTCPFlags] = 0x10   // ACK
	binary.BigEndian.PutUint16(s.ackPkt[offTCPWindow:], 64240)

	// Build UDP template
	buildEthHeader(s.udpPkt[:], srcMAC, dstMAC)
	buildIPv4HeaderProto(s.udpPkt[:], srcIP4, udpHdrLen, 17) // protocol 17 = UDP

	return s, nil
}

func buildEthHeader(pkt []byte, srcMAC, dstMAC net.HardwareAddr) {
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // EtherType IPv4
}

func buildIPv4Header(pkt []byte, srcIP net.IP, tcpLen int) {
	buildIPv4HeaderProto(pkt, srcIP, tcpLen, 6) // protocol 6 = TCP
}

func buildIPv4HeaderProto(pkt []byte, srcIP net.IP, transportLen int, proto byte) {
	pkt[ipOff+0] = 0x45 // Version=4, IHL=5 (20 bytes)
	pkt[ipOff+1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[offIPTotalLen:], uint16(ipLen+transportLen))
	// IP.Id, Checksum: set per-packet
	pkt[ipOff+6] = 0x40 // Flags: Don't Fragment
	pkt[ipOff+7] = 0x00 // Fragment Offset
	pkt[ipOff+8] = 64   // TTL
	pkt[ipOff+9] = proto
	copy(pkt[offIPSrcIP:offIPSrcIP+4], srcIP)
}

// GenerateCookie creates a stateless SYN Cookie. Zero allocations.
func (s *RingSender) GenerateCookie(dstIP uint32, dstPort uint16) uint32 {
	const prime32 = uint32(16777619)
	h := uint32(2166136261) // FNV offset basis
	h ^= uint32(s.cookieSecret)
	h *= prime32
	h ^= uint32(s.cookieSecret >> 32)
	h *= prime32
	h ^= dstIP
	h *= prime32
	h ^= uint32(dstPort)
	h *= prime32
	return h
}

// SendSYNWithPort sends a SYN by patching the template in place.
// Zero heap allocations per call.
func (s *RingSender) SendSYNWithPort(dstIP uint32, dstPort, srcPort uint16) error {
	pkt := &s.synPkt

	// Patch IP.Id (incrementing avoids the all-zero scanner fingerprint)
	s.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)

	// Patch DstIP
	binary.BigEndian.PutUint32(pkt[offIPDstIP:], dstIP)

	// Recompute IP checksum
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	// Patch TCP fields
	binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offTCPDstPort:], dstPort)
	binary.BigEndian.PutUint32(pkt[offTCPSeq:], s.GenerateCookie(dstIP, dstPort))

	// Recompute TCP checksum
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:synPktLen]))

	return s.handle.WritePacketData(pkt[:])
}

// SendACK sends an ACK with the correct 4-tuple for banner grabbing.
func (s *RingSender) SendACK(dstIP net.IP, dstPort, srcPort int, seq, ack uint32) error {
	pkt := &s.ackPkt

	s.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)

	copy(pkt[offIPDstIP:offIPDstIP+4], dstIP.To4())

	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[offTCPDstPort:], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[offTCPSeq:], seq)
	binary.BigEndian.PutUint32(pkt[offTCPAck:], ack)

	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:ackPktLen]))

	return s.handle.WritePacketData(pkt[:])
}

// SendRST sends a RST packet to tear down a connection.
func (s *RingSender) SendRST(dstIP net.IP, dstPort, srcPort int, seq uint32) error {
	pkt := &s.ackPkt // reuse ACK template (same size, 20-byte TCP header)

	s.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)

	copy(pkt[offIPDstIP:offIPDstIP+4], dstIP.To4())

	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[offTCPDstPort:], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[offTCPSeq:], seq)
	binary.BigEndian.PutUint32(pkt[offTCPAck:], 0)

	pkt[offTCPFlags] = 0x04 // RST

	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:ackPktLen]))

	err := s.handle.WritePacketData(pkt[:])

	// Restore ACK flag for the template
	pkt[offTCPFlags] = 0x10
	return err
}

// SendData sends a PSH+ACK packet with a payload (hello, negotiate reply).
// Uses pre-allocated scratch buffer — zero heap allocations for payloads ≤ MTU.
func (s *RingSender) SendData(dstIP net.IP, dstPort, srcPort int, seq, ack uint32, payload []byte) error {
	pktLen := ethLen + ipLen + ackTCPLen + len(payload)

	// Use scratch buffer for normal-sized packets, fall back to alloc for jumbo
	var pkt []byte
	if pktLen <= maxPayloadPkt {
		pkt = s.scratch[:pktLen]
	} else {
		pkt = make([]byte, pktLen)
	}

	// Copy the ACK template for eth + ip + tcp headers
	copy(pkt, s.ackPkt[:ackPktLen])

	// Fix IP total length
	binary.BigEndian.PutUint16(pkt[offIPTotalLen:], uint16(ipLen+ackTCPLen+len(payload)))

	s.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)

	copy(pkt[offIPDstIP:offIPDstIP+4], dstIP.To4())

	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[offTCPDstPort:], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[offTCPSeq:], seq)
	binary.BigEndian.PutUint32(pkt[offTCPAck:], ack)

	pkt[offTCPFlags] = 0x18 // PSH + ACK

	// Copy payload after TCP header
	copy(pkt[ackPktLen:], payload)

	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:pktLen]))

	return s.handle.WritePacketData(pkt)
}

// SendUDP sends a UDP datagram with the given payload.
// Uses pre-allocated scratch buffer — zero heap allocations for payloads ≤ MTU.
func (s *RingSender) SendUDP(dstIP uint32, dstPort, srcPort uint16, payload []byte) error {
	pktLen := udpBasePktLen + len(payload)

	var pkt []byte
	if pktLen <= maxPayloadPkt {
		pkt = s.scratch[:pktLen]
	} else {
		pkt = make([]byte, pktLen)
	}

	// Copy UDP template for eth + ip + udp headers
	copy(pkt, s.udpPkt[:udpBasePktLen])

	// Fix IP total length
	binary.BigEndian.PutUint16(pkt[offIPTotalLen:], uint16(ipLen+udpHdrLen+len(payload)))

	s.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)

	// Patch DstIP
	binary.BigEndian.PutUint32(pkt[offIPDstIP:], dstIP)

	// Recompute IP checksum
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	// Patch UDP fields
	binary.BigEndian.PutUint16(pkt[offUDPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offUDPDstPort:], dstPort)
	binary.BigEndian.PutUint16(pkt[offUDPLength:], uint16(udpHdrLen+len(payload)))

	// Copy payload after UDP header
	copy(pkt[udpBasePktLen:], payload)

	// Compute UDP checksum
	binary.BigEndian.PutUint16(pkt[offUDPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offUDPChecksum:],
		transportChecksum(17, pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[udpOff:pktLen]))

	return s.handle.WritePacketData(pkt)
}

// ipChecksum computes the IPv4 header checksum per RFC 1071.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the pseudo-header + segment.
func tcpChecksum(srcIP, dstIP, segment []byte) uint16 {
	return transportChecksum(6, srcIP, dstIP, segment)
}

// transportChecksum computes the checksum over a pseudo-header + transport segment.
// proto is the IP protocol number (6=TCP, 17=UDP).
func transportChecksum(proto uint16, srcIP, dstIP, segment []byte) uint16 {
	segLen := len(segment)
	var sum uint32

	// Pseudo-header
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(proto)
	sum += uint32(segLen)

	// Transport segment
	for i := 0; i < segLen-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[i:]))
	}
	if segLen%2 == 1 {
		sum += uint32(segment[segLen-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// Close releases AF_PACKET resources.
func (s *RingSender) Close() {
	s.handle.Close()
}
