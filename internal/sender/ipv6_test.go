package sender

import (
	"encoding/binary"
	"testing"
)

// TestBuildIPv6SYN constructs an IPv6 SYN packet and validates all header fields.
func TestBuildIPv6SYN(t *testing.T) {
	s := &RingSender{cookieSecret: 0xDEADBEEFCAFEBABE, ipID: 1}

	// Configure IPv6 with a test source address
	var srcIPv6 [16]byte
	srcIPv6[0] = 0x20; srcIPv6[1] = 0x01 // 2001:db8::1
	srcIPv6[2] = 0x0d; srcIPv6[3] = 0xb8
	srcIPv6[15] = 0x01

	srcMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	s.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)

	if !s.hasV6 {
		t.Fatal("hasV6 should be true after ConfigureIPv6")
	}

	pkt := s.synPktV6[:]

	// Verify Ethernet header: EtherType = 0x86DD (IPv6)
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != 0x86DD {
		t.Fatalf("EtherType = 0x%04X, want 0x86DD", etherType)
	}

	// Verify dst/src MAC
	for i := 0; i < 6; i++ {
		if pkt[i] != dstMAC[i] {
			t.Fatalf("DstMAC[%d] = 0x%02X, want 0x%02X", i, pkt[i], dstMAC[i])
		}
		if pkt[6+i] != srcMAC[i] {
			t.Fatalf("SrcMAC[%d] = 0x%02X, want 0x%02X", i, pkt[6+i], srcMAC[i])
		}
	}

	// Verify IPv6 header
	version := pkt[ethLen] >> 4
	if version != 6 {
		t.Fatalf("IP version = %d, want 6", version)
	}

	payloadLen := binary.BigEndian.Uint16(pkt[offV6PayloadLen:])
	if payloadLen != uint16(synTCPLen) {
		t.Fatalf("PayloadLen = %d, want %d (synTCPLen)", payloadLen, synTCPLen)
	}

	nextHeader := pkt[offV6NextHeader]
	if nextHeader != 6 {
		t.Fatalf("NextHeader = %d, want 6 (TCP)", nextHeader)
	}

	hopLimit := pkt[offV6HopLimit]
	if hopLimit != 64 {
		t.Fatalf("HopLimit = %d, want 64", hopLimit)
	}

	// Verify source IP in template
	var gotSrcIP [16]byte
	copy(gotSrcIP[:], pkt[offV6SrcIP:offV6SrcIP+16])
	if gotSrcIP != srcIPv6 {
		t.Fatalf("SrcIP mismatch")
	}

	// Verify TCP SYN flag
	if pkt[offV6TCPFlags] != 0x02 {
		t.Fatalf("TCP flags = 0x%02X, want 0x02 (SYN)", pkt[offV6TCPFlags])
	}

	// Verify TCP data offset = 10 words (40 bytes: 20 hdr + 20 opts)
	if pkt[offV6TCPDataOff] != 0xA0 {
		t.Fatalf("TCP DataOff = 0x%02X, want 0xA0", pkt[offV6TCPDataOff])
	}

	// Verify window size
	window := binary.BigEndian.Uint16(pkt[offV6TCPWindow:])
	if window != 64240 {
		t.Fatalf("TCP Window = %d, want 64240", window)
	}

	// Verify total packet length
	if len(pkt) != synPktLenV6 {
		t.Fatalf("Packet length = %d, want %d", len(pkt), synPktLenV6)
	}
}

// TestIPv6ChecksumCorrectness verifies the IPv6 TCP checksum computation.
func TestIPv6ChecksumCorrectness(t *testing.T) {
	// Build a minimal TCP segment with known values
	srcIP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	// Simple 20-byte TCP header (ACK)
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:], 40000)  // src port
	binary.BigEndian.PutUint16(segment[2:], 80)      // dst port
	binary.BigEndian.PutUint32(segment[4:], 100)     // seq
	binary.BigEndian.PutUint32(segment[8:], 200)     // ack
	segment[12] = 0x50 // data offset = 5 words
	segment[13] = 0x10 // ACK flag
	binary.BigEndian.PutUint16(segment[14:], 64240)  // window

	csum := transportChecksumV6(6, srcIP[:], dstIP[:], segment)
	if csum == 0 {
		t.Fatal("checksum should not be zero for non-trivial data")
	}

	// Verify: computing checksum over segment-with-checksum should yield 0
	binary.BigEndian.PutUint16(segment[16:], csum)
	verify := transportChecksumV6(6, srcIP[:], dstIP[:], segment)
	if verify != 0 {
		t.Fatalf("checksum verification failed: got 0x%04X, want 0x0000", verify)
	}
}

// TestIsIPv4Mapped verifies the IPv4-mapped address detection.
func TestIsIPv4Mapped(t *testing.T) {
	tests := []struct {
		name string
		ip   [16]byte
		want bool
	}{
		{"IPv4 mapped", u32ToIP16(0xC0A80001), true},
		{"IPv6 native", [16]byte{0x20, 0x01, 0x0d, 0xb8}, false},
		{"Zero", [16]byte{}, false},
		{"Loopback v6", [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIPv4Mapped(tt.ip)
			if got != tt.want {
				t.Errorf("isIPv4Mapped = %v, want %v", got, tt.want)
			}
		})
	}
}

// BenchmarkBuildSYNPacketV6 measures IPv6 SYN construction speed.
func BenchmarkBuildSYNPacketV6(b *testing.B) {
	s := &RingSender{cookieSecret: 0xDEADBEEFCAFEBABE, ipID: 1}

	var srcIPv6 [16]byte
	srcIPv6[0] = 0x20; srcIPv6[1] = 0x01; srcIPv6[2] = 0x0d; srcIPv6[3] = 0xb8
	srcIPv6[15] = 0x01

	srcMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	s.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := &s.synPktV6
		var dstIP [16]byte
		dstIP[0] = 0x20; dstIP[1] = 0x01; dstIP[2] = 0x0d; dstIP[3] = 0xb8
		binary.BigEndian.PutUint32(dstIP[12:], uint32(i))

		copy(pkt[offV6DstIP:offV6DstIP+16], dstIP[:])
		binary.BigEndian.PutUint16(pkt[offV6TCPSrcPort:], uint16(32768+i%17232))
		binary.BigEndian.PutUint16(pkt[offV6TCPDstPort:], 80)
		binary.BigEndian.PutUint32(pkt[offV6TCPSeq:], s.GenerateCookie(dstIP, 80))
		binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:], 0)
		binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:],
			transportChecksumV6(6, pkt[offV6SrcIP:offV6SrcIP+16], pkt[offV6DstIP:offV6DstIP+16], pkt[tcpOffV6:synPktLenV6]))
	}
}
