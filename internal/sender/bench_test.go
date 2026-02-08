package sender

import (
	"encoding/binary"
	"net"
	"testing"
)

func BenchmarkGenerateCookie(b *testing.B) {
	s := &RingSender{cookieSecret: 0xDEADBEEFCAFEBABE}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateCookie(uint32(i), 80)
	}
}

func BenchmarkIPChecksum(b *testing.B) {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:], 40)
	hdr[8] = 64
	hdr[9] = 6
	copy(hdr[12:16], net.IP{192, 168, 1, 1})
	copy(hdr[16:20], net.IP{10, 0, 0, 1})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ipChecksum(hdr)
	}
}

func BenchmarkTCPChecksum(b *testing.B) {
	srcIP := []byte{192, 168, 1, 1}
	dstIP := []byte{10, 0, 0, 1}
	segment := make([]byte, 24) // SYN with MSS option
	segment[12] = 0x60
	segment[13] = 0x02
	binary.BigEndian.PutUint16(segment[14:], 64240)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tcpChecksum(srcIP, dstIP, segment)
	}
}

func BenchmarkBuildSYNPacket(b *testing.B) {
	// Simulate the per-packet work of SendSYNWithPort without AF_PACKET
	s := &RingSender{cookieSecret: 0xDEADBEEFCAFEBABE, ipID: 1}

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	srcIP := net.IP{192, 168, 1, 1}.To4()

	buildEthHeader(s.synPkt[:], srcMAC, dstMAC)
	buildIPv4Header(s.synPkt[:], srcIP, synTCPLen)
	s.synPkt[offTCPDataOff] = 0x60
	s.synPkt[offTCPFlags] = 0x02
	binary.BigEndian.PutUint16(s.synPkt[offTCPWindow:], 64240)
	s.synPkt[tcpOff+20] = 2
	s.synPkt[tcpOff+21] = 4
	s.synPkt[tcpOff+22] = 0x05
	s.synPkt[tcpOff+23] = 0xB4

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := &s.synPkt
		dstIP := uint32(0x0A000000 + i)
		dstPort := uint16(80)
		srcPort := uint16(32768 + i%28232)

		s.ipID++
		binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)
		binary.BigEndian.PutUint32(pkt[offIPDstIP:], dstIP)
		binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
		binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))
		binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], srcPort)
		binary.BigEndian.PutUint16(pkt[offTCPDstPort:], dstPort)
		binary.BigEndian.PutUint32(pkt[offTCPSeq:], s.GenerateCookie(dstIP, dstPort))
		binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
		binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
			tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:synPktLen]))
	}
}

func BenchmarkBuildACKPacket(b *testing.B) {
	s := &RingSender{cookieSecret: 0xDEADBEEFCAFEBABE, ipID: 1}

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	srcIP := net.IP{192, 168, 1, 1}.To4()

	buildEthHeader(s.ackPkt[:], srcMAC, dstMAC)
	buildIPv4Header(s.ackPkt[:], srcIP, ackTCPLen)
	s.ackPkt[offTCPDataOff] = 0x50
	s.ackPkt[offTCPFlags] = 0x10
	binary.BigEndian.PutUint16(s.ackPkt[offTCPWindow:], 64240)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := &s.ackPkt
		dstIP := uint32(0x0A000000 + i)

		s.ipID++
		binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)
		binary.BigEndian.PutUint32(pkt[offIPDstIP:], dstIP)
		binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
		binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))
		binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], uint16(40000+i%20000))
		binary.BigEndian.PutUint16(pkt[offTCPDstPort:], 80)
		binary.BigEndian.PutUint32(pkt[offTCPSeq:], uint32(i))
		binary.BigEndian.PutUint32(pkt[offTCPAck:], uint32(i+1))
		binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
		binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
			tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:ackPktLen]))
	}
}
