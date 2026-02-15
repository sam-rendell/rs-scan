package sender

import (
	"crypto/rand"
	"encoding/binary"
	"net"
)

// packetWriter abstracts AF_PACKET (linux) vs pcap (darwin) for injection.
type packetWriter interface {
	WritePacketData([]byte) error
	Close()
}

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

	// TCP field offsets (absolute from packet start, IPv4)
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

	// UDP field offsets (absolute from packet start, IPv4)
	udpOff         = ipOff + ipLen // 34 (same position as TCP)
	udpHdrLen      = 8
	udpBasePktLen  = ethLen + ipLen + udpHdrLen // 42 (no payload)
	offUDPSrcPort  = udpOff + 0  // 34
	offUDPDstPort  = udpOff + 2  // 36
	offUDPLength   = udpOff + 4  // 38
	offUDPChecksum = udpOff + 6  // 40
)

// IPv6 packet layout constants.
const (
	ipv6Len  = 40
	tcpOffV6 = ethLen + ipv6Len // 54

	// IPv6 field offsets (absolute from packet start)
	offV6PayloadLen = ethLen + 4  // 18
	offV6NextHeader = ethLen + 6  // 20
	offV6HopLimit   = ethLen + 7  // 21
	offV6SrcIP      = ethLen + 8  // 22
	offV6DstIP      = ethLen + 24 // 38

	// TCP field offsets for IPv6 (absolute from packet start)
	offV6TCPSrcPort  = tcpOffV6 + 0  // 54
	offV6TCPDstPort  = tcpOffV6 + 2  // 56
	offV6TCPSeq      = tcpOffV6 + 4  // 58
	offV6TCPAck      = tcpOffV6 + 8  // 62
	offV6TCPDataOff  = tcpOffV6 + 12 // 66
	offV6TCPFlags    = tcpOffV6 + 13 // 67
	offV6TCPWindow   = tcpOffV6 + 14 // 68
	offV6TCPChecksum = tcpOffV6 + 16 // 70

	// IPv6 SYN: Eth(14) + IPv6(40) + TCP(40 with opts) = 94
	synPktLenV6 = ethLen + ipv6Len + synTCPLen // 94

	// IPv6 ACK: Eth(14) + IPv6(40) + TCP(20) = 74
	ackPktLenV6 = ethLen + ipv6Len + ackTCPLen // 74

	// UDP field offsets for IPv6 (absolute from packet start)
	udpOffV6         = ethLen + ipv6Len // 54
	udpBasePktLenV6  = ethLen + ipv6Len + udpHdrLen // 62
	offV6UDPSrcPort  = udpOffV6 + 0  // 54
	offV6UDPDstPort  = udpOffV6 + 2  // 56
	offV6UDPLength   = udpOffV6 + 4  // 58
	offV6UDPChecksum = udpOffV6 + 6  // 60
)

// maxPayloadPkt is the max packet size for SendData/SendUDP scratch buffer.
// Eth(14) + IP(20) + TCP/UDP(20) + payload(≤1460) = 1514 (standard MTU frame).
const maxPayloadPkt = 1514

// RingSender handles high-speed packet injection.
// Packets are built by patching a pre-built template — zero allocations per packet.
type RingSender struct {
	handle       packetWriter
	synPkt       [synPktLen]byte
	ackPkt       [ackPktLen]byte
	udpPkt       [udpBasePktLen]byte         // base UDP template (no payload)
	synPktV6     [synPktLenV6]byte           // IPv6 SYN template
	ackPktV6     [ackPktLenV6]byte           // IPv6 ACK template
	udpPktV6     [udpBasePktLenV6]byte       // IPv6 UDP template
	scratch      [maxPayloadPkt]byte         // reusable buffer for SendData/SendUDP
	cookieSecret uint64
	ipID         uint16
	writeOff     int                         // 0 for Ethernet, ethLen (14) for TUN
	hasV6        bool                        // true if IPv6 templates are initialized
}

// NewRingSender initializes a packet injection handle for sending.
func NewRingSender(iface string, srcMAC, dstMAC net.HardwareAddr, srcIP net.IP) (*RingSender, error) {
	// TUN/point-to-point: no Ethernet header on wire.
	// Use tunnelWriter (AF_PACKET SOCK_DGRAM) instead of TPacket SOCK_RAW so that
	// the kernel sets the correct link-layer protocol (needed for GRE tunnels).
	isTUN := len(srcMAC) == 0
	var handle packetWriter
	var err error
	if isTUN {
		handle, err = newTunnelWriter(iface)
	} else {
		handle, err = newPacketWriter(iface)
	}
	if err != nil {
		return nil, err
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

	if isTUN {
		s.writeOff = ethLen
	}

	// Build IPv4 templates (skipped for IPv6-only interfaces where srcIP is nil)
	if srcIP != nil {
		srcIP4 := srcIP.To4()
		// Build SYN template (static fields only — mutable fields patched per-packet)
		// Options mimic a standard Linux 5.x stack so remote hosts negotiate full
		// option sets in their SYN-ACK, enabling passive OS fingerprinting.
		if !isTUN {
			buildEthHeader(s.synPkt[:], srcMAC, dstMAC)
		}
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
		if !isTUN {
			buildEthHeader(s.ackPkt[:], srcMAC, dstMAC)
		}
		buildIPv4Header(s.ackPkt[:], srcIP4, ackTCPLen)
		s.ackPkt[offTCPDataOff] = 0x50 // Data Offset = 5 words (20 bytes)
		s.ackPkt[offTCPFlags] = 0x10   // ACK
		binary.BigEndian.PutUint16(s.ackPkt[offTCPWindow:], 64240)

		// Build UDP template
		if !isTUN {
			buildEthHeader(s.udpPkt[:], srcMAC, dstMAC)
		}
		buildIPv4HeaderProto(s.udpPkt[:], srcIP4, udpHdrLen, 17) // protocol 17 = UDP
	}

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

func buildEthHeaderV6(pkt []byte, srcMAC, dstMAC net.HardwareAddr) {
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:14], 0x86DD) // EtherType IPv6
}

func buildIPv6Header(pkt []byte, srcIP [16]byte, nextHeader byte, payloadLen int) {
	pkt[ethLen+0] = 0x60 // Version=6, Traffic Class=0
	pkt[ethLen+1] = 0x00
	pkt[ethLen+2] = 0x00 // Flow Label = 0
	pkt[ethLen+3] = 0x00
	binary.BigEndian.PutUint16(pkt[offV6PayloadLen:], uint16(payloadLen))
	pkt[offV6NextHeader] = nextHeader
	pkt[offV6HopLimit] = 64
	copy(pkt[offV6SrcIP:offV6SrcIP+16], srcIP[:])
	// DstIP is set per-packet
}

// ConfigureIPv6 builds IPv6 packet templates for dual-stack scanning.
// srcIPv6 must be a full 16-byte IPv6 address. Call after NewRingSender.
func (s *RingSender) ConfigureIPv6(srcIPv6 [16]byte, srcMAC, dstMAC net.HardwareAddr) {
	isTUN := s.writeOff == ethLen

	// SYN template
	if !isTUN {
		buildEthHeaderV6(s.synPktV6[:], srcMAC, dstMAC)
	}
	buildIPv6Header(s.synPktV6[:], srcIPv6, 6, synTCPLen) // Next Header = TCP
	s.synPktV6[offV6TCPDataOff] = 0xA0 // Data Offset = 10 words (40 bytes)
	s.synPktV6[offV6TCPFlags] = 0x02   // SYN
	binary.BigEndian.PutUint16(s.synPktV6[offV6TCPWindow:], 64240)
	o := tcpOffV6 + 20
	s.synPktV6[o+0] = 2; s.synPktV6[o+1] = 4; s.synPktV6[o+2] = 0x05; s.synPktV6[o+3] = 0xB4 // MSS 1440 for v6
	s.synPktV6[o+4] = 4; s.synPktV6[o+5] = 2                                                    // SACK
	s.synPktV6[o+6] = 8; s.synPktV6[o+7] = 10                                                    // Timestamps
	binary.BigEndian.PutUint32(s.synPktV6[o+8:], uint32(s.cookieSecret))
	s.synPktV6[o+16] = 1                                                                          // NOP
	s.synPktV6[o+17] = 3; s.synPktV6[o+18] = 3; s.synPktV6[o+19] = 7                            // WScale=7

	// ACK template
	if !isTUN {
		buildEthHeaderV6(s.ackPktV6[:], srcMAC, dstMAC)
	}
	buildIPv6Header(s.ackPktV6[:], srcIPv6, 6, ackTCPLen)
	s.ackPktV6[offV6TCPDataOff] = 0x50 // Data Offset = 5 words
	s.ackPktV6[offV6TCPFlags] = 0x10   // ACK
	binary.BigEndian.PutUint16(s.ackPktV6[offV6TCPWindow:], 64240)

	// UDP template
	if !isTUN {
		buildEthHeaderV6(s.udpPktV6[:], srcMAC, dstMAC)
	}
	buildIPv6Header(s.udpPktV6[:], srcIPv6, 17, udpHdrLen)

	s.hasV6 = true
}

// isIPv4Mapped returns true if the [16]byte is an IPv4-mapped address (::ffff:x.x.x.x).
func isIPv4Mapped(ip [16]byte) bool {
	return ip[10] == 0xFF && ip[11] == 0xFF &&
		ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0
}

// GenerateCookie creates a stateless SYN Cookie. Zero allocations.
// dstIP is a [16]byte for dual IPv4/IPv6 support (Phase 1: IPv4 uses last 4 bytes).
func (s *RingSender) GenerateCookie(dstIP [16]byte, dstPort uint16) uint32 {
	const prime32 = uint32(16777619)
	h := uint32(2166136261) // FNV offset basis
	h ^= uint32(s.cookieSecret)
	h *= prime32
	h ^= uint32(s.cookieSecret >> 32)
	h *= prime32
	// Hash all 16 bytes of IP
	for i := 0; i < 16; i += 4 {
		v := uint32(dstIP[i])<<24 | uint32(dstIP[i+1])<<16 | uint32(dstIP[i+2])<<8 | uint32(dstIP[i+3])
		h ^= v
		h *= prime32
	}
	h ^= uint32(dstPort)
	h *= prime32
	return h
}

// SendSYNWithPort sends a SYN by patching the template in place.
// Zero heap allocations per call.
// dstIP is a [16]byte: IPv4-mapped (::ffff:x.x.x.x) uses IPv4 template, otherwise IPv6.
func (s *RingSender) SendSYNWithPort(dstIP [16]byte, dstPort, srcPort uint16) error {
	if !isIPv4Mapped(dstIP) && s.hasV6 {
		return s.sendSYNv6(dstIP, dstPort, srcPort)
	}
	return s.sendSYNv4(dstIP, dstPort, srcPort)
}

func (s *RingSender) sendSYNv4(dstIP [16]byte, dstPort, srcPort uint16) error {
	pkt := &s.synPkt

	s.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)
	copy(pkt[offIPDstIP:offIPDstIP+4], dstIP[12:16])

	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offTCPDstPort:], dstPort)
	binary.BigEndian.PutUint32(pkt[offTCPSeq:], s.GenerateCookie(dstIP, dstPort))

	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:synPktLen]))

	return s.handle.WritePacketData(pkt[s.writeOff:])
}

func (s *RingSender) sendSYNv6(dstIP [16]byte, dstPort, srcPort uint16) error {
	pkt := &s.synPktV6

	copy(pkt[offV6DstIP:offV6DstIP+16], dstIP[:])

	binary.BigEndian.PutUint16(pkt[offV6TCPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offV6TCPDstPort:], dstPort)
	binary.BigEndian.PutUint32(pkt[offV6TCPSeq:], s.GenerateCookie(dstIP, dstPort))

	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:],
		transportChecksumV6(6, pkt[offV6SrcIP:offV6SrcIP+16], pkt[offV6DstIP:offV6DstIP+16], pkt[tcpOffV6:synPktLenV6]))

	return s.handle.WritePacketData(pkt[s.writeOff:])
}

// SendACK sends an ACK with the correct 4-tuple for banner grabbing.
func (s *RingSender) SendACK(dstIP net.IP, dstPort, srcPort int, seq, ack uint32) error {
	if dstIP.To4() == nil && s.hasV6 {
		return s.sendACKv6(dstIP, dstPort, srcPort, seq, ack)
	}
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

	return s.handle.WritePacketData(pkt[s.writeOff:])
}

func (s *RingSender) sendACKv6(dstIP net.IP, dstPort, srcPort int, seq, ack uint32) error {
	pkt := &s.ackPktV6

	copy(pkt[offV6DstIP:offV6DstIP+16], dstIP.To16())

	binary.BigEndian.PutUint16(pkt[offV6TCPSrcPort:], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[offV6TCPDstPort:], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[offV6TCPSeq:], seq)
	binary.BigEndian.PutUint32(pkt[offV6TCPAck:], ack)

	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:],
		transportChecksumV6(6, pkt[offV6SrcIP:offV6SrcIP+16], pkt[offV6DstIP:offV6DstIP+16], pkt[tcpOffV6:ackPktLenV6]))

	return s.handle.WritePacketData(pkt[s.writeOff:])
}

// SendRST sends a RST packet to tear down a connection.
func (s *RingSender) SendRST(dstIP net.IP, dstPort, srcPort int, seq uint32) error {
	if dstIP.To4() == nil && s.hasV6 {
		return s.sendRSTv6(dstIP, dstPort, srcPort, seq)
	}
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

	err := s.handle.WritePacketData(pkt[s.writeOff:])
	pkt[offTCPFlags] = 0x10
	return err
}

func (s *RingSender) sendRSTv6(dstIP net.IP, dstPort, srcPort int, seq uint32) error {
	pkt := &s.ackPktV6

	copy(pkt[offV6DstIP:offV6DstIP+16], dstIP.To16())

	binary.BigEndian.PutUint16(pkt[offV6TCPSrcPort:], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[offV6TCPDstPort:], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[offV6TCPSeq:], seq)
	binary.BigEndian.PutUint32(pkt[offV6TCPAck:], 0)

	pkt[offV6TCPFlags] = 0x04 // RST

	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:],
		transportChecksumV6(6, pkt[offV6SrcIP:offV6SrcIP+16], pkt[offV6DstIP:offV6DstIP+16], pkt[tcpOffV6:ackPktLenV6]))

	err := s.handle.WritePacketData(pkt[s.writeOff:])
	pkt[offV6TCPFlags] = 0x10
	return err
}

// SendData sends a PSH+ACK packet with a payload (hello, negotiate reply).
// Uses pre-allocated scratch buffer — zero heap allocations for payloads ≤ MTU.
func (s *RingSender) SendData(dstIP net.IP, dstPort, srcPort int, seq, ack uint32, payload []byte) error {
	if dstIP.To4() == nil && s.hasV6 {
		return s.sendDataV6(dstIP, dstPort, srcPort, seq, ack, payload)
	}
	pktLen := ethLen + ipLen + ackTCPLen + len(payload)

	var pkt []byte
	if pktLen <= maxPayloadPkt {
		pkt = s.scratch[:pktLen]
	} else {
		pkt = make([]byte, pktLen)
	}

	copy(pkt, s.ackPkt[:ackPktLen])
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

	copy(pkt[ackPktLen:], payload)

	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:pktLen]))

	return s.handle.WritePacketData(pkt[s.writeOff:])
}

func (s *RingSender) sendDataV6(dstIP net.IP, dstPort, srcPort int, seq, ack uint32, payload []byte) error {
	pktLen := ackPktLenV6 + len(payload)

	var pkt []byte
	if pktLen <= maxPayloadPkt {
		pkt = s.scratch[:pktLen]
	} else {
		pkt = make([]byte, pktLen)
	}

	copy(pkt, s.ackPktV6[:ackPktLenV6])
	binary.BigEndian.PutUint16(pkt[offV6PayloadLen:], uint16(ackTCPLen+len(payload)))

	copy(pkt[offV6DstIP:offV6DstIP+16], dstIP.To16())

	binary.BigEndian.PutUint16(pkt[offV6TCPSrcPort:], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[offV6TCPDstPort:], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[offV6TCPSeq:], seq)
	binary.BigEndian.PutUint32(pkt[offV6TCPAck:], ack)
	pkt[offV6TCPFlags] = 0x18 // PSH + ACK

	copy(pkt[ackPktLenV6:], payload)

	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:],
		transportChecksumV6(6, pkt[offV6SrcIP:offV6SrcIP+16], pkt[offV6DstIP:offV6DstIP+16], pkt[tcpOffV6:pktLen]))

	return s.handle.WritePacketData(pkt[s.writeOff:])
}

// SendUDP sends a UDP datagram with the given payload.
// Uses pre-allocated scratch buffer — zero heap allocations for payloads ≤ MTU.
// dstIP is a [16]byte: IPv4-mapped uses IPv4 template, otherwise IPv6.
func (s *RingSender) SendUDP(dstIP [16]byte, dstPort, srcPort uint16, payload []byte) error {
	if !isIPv4Mapped(dstIP) && s.hasV6 {
		return s.sendUDPv6(dstIP, dstPort, srcPort, payload)
	}
	pktLen := udpBasePktLen + len(payload)

	var pkt []byte
	if pktLen <= maxPayloadPkt {
		pkt = s.scratch[:pktLen]
	} else {
		pkt = make([]byte, pktLen)
	}

	copy(pkt, s.udpPkt[:udpBasePktLen])
	binary.BigEndian.PutUint16(pkt[offIPTotalLen:], uint16(ipLen+udpHdrLen+len(payload)))

	s.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)
	copy(pkt[offIPDstIP:offIPDstIP+4], dstIP[12:16])

	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	binary.BigEndian.PutUint16(pkt[offUDPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offUDPDstPort:], dstPort)
	binary.BigEndian.PutUint16(pkt[offUDPLength:], uint16(udpHdrLen+len(payload)))

	copy(pkt[udpBasePktLen:], payload)

	binary.BigEndian.PutUint16(pkt[offUDPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offUDPChecksum:],
		transportChecksum(17, pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[udpOff:pktLen]))

	return s.handle.WritePacketData(pkt[s.writeOff:])
}

func (s *RingSender) sendUDPv6(dstIP [16]byte, dstPort, srcPort uint16, payload []byte) error {
	pktLen := udpBasePktLenV6 + len(payload)

	var pkt []byte
	if pktLen <= maxPayloadPkt {
		pkt = s.scratch[:pktLen]
	} else {
		pkt = make([]byte, pktLen)
	}

	copy(pkt, s.udpPktV6[:udpBasePktLenV6])
	binary.BigEndian.PutUint16(pkt[offV6PayloadLen:], uint16(udpHdrLen+len(payload)))

	copy(pkt[offV6DstIP:offV6DstIP+16], dstIP[:])

	binary.BigEndian.PutUint16(pkt[offV6UDPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offV6UDPDstPort:], dstPort)
	binary.BigEndian.PutUint16(pkt[offV6UDPLength:], uint16(udpHdrLen+len(payload)))

	copy(pkt[udpBasePktLenV6:], payload)

	binary.BigEndian.PutUint16(pkt[offV6UDPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offV6UDPChecksum:],
		transportChecksumV6(17, pkt[offV6SrcIP:offV6SrcIP+16], pkt[offV6DstIP:offV6DstIP+16], pkt[udpOffV6:pktLen]))

	return s.handle.WritePacketData(pkt[s.writeOff:])
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

// transportChecksumV6 computes the transport checksum with an IPv6 pseudo-header.
// IPv6 pseudo-header: srcIP(16) + dstIP(16) + upper-layer length(4) + zeros(3) + next-header(1).
func transportChecksumV6(proto uint16, srcIP, dstIP, segment []byte) uint16 {
	segLen := len(segment)
	var sum uint32

	// Pseudo-header: source address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	// Pseudo-header: destination address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	// Pseudo-header: upper-layer packet length (4 bytes, big-endian)
	sum += uint32(segLen)
	// Pseudo-header: zero(3) + next header(1)
	sum += uint32(proto)

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

// Close releases the packet injection handle.
func (s *RingSender) Close() {
	s.handle.Close()
}
