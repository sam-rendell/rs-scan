package sender

import (
	"encoding/binary"
	"testing"
)

func TestTransportChecksum_TCP(t *testing.T) {
	// Verify that transportChecksum(6, ...) equals tcpChecksum(...)
	srcIP := []byte{192, 168, 1, 1}
	dstIP := []byte{192, 168, 1, 2}
	// Minimal TCP segment: 20 bytes header
	segment := make([]byte, 20)
	segment[0] = 0xC0 // src port high
	segment[1] = 0x00 // src port low = 49152
	segment[2] = 0x00
	segment[3] = 0x50 // dst port = 80
	segment[12] = 0x50 // data offset = 5 words, no flags

	got := transportChecksum(6, srcIP, dstIP, segment)
	want := tcpChecksum(srcIP, dstIP, segment)
	if got != want {
		t.Fatalf("transportChecksum(6) = %04x, tcpChecksum = %04x", got, want)
	}
}

func TestTransportChecksum_UDP(t *testing.T) {
	srcIP := []byte{10, 0, 0, 1}
	dstIP := []byte{10, 0, 0, 2}
	// UDP segment: 8 byte header + "hello" payload
	payload := []byte("hello")
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:], 50000) // src port
	binary.BigEndian.PutUint16(segment[2:], 53)    // dst port
	binary.BigEndian.PutUint16(segment[4:], uint16(8+len(payload))) // length
	// checksum field = 0
	copy(segment[8:], payload)

	cksum := transportChecksum(17, srcIP, dstIP, segment)
	if cksum == 0 {
		t.Fatal("UDP checksum should not be 0")
	}

	// Verify: put checksum into segment, recompute should be 0 (or 0xFFFF for UDP)
	binary.BigEndian.PutUint16(segment[6:], cksum)
	verify := transportChecksum(17, srcIP, dstIP, segment)
	if verify != 0 {
		t.Fatalf("UDP checksum verification failed: got %04x, want 0", verify)
	}
}

func TestUDPPacketTemplate(t *testing.T) {
	// Verify the UDP packet template has correct structure
	s := &RingSender{}
	// We can't fully initialize without AF_PACKET, but we can test field offsets
	if udpOff != 34 {
		t.Fatalf("udpOff = %d, want 34", udpOff)
	}
	if udpBasePktLen != 42 {
		t.Fatalf("udpBasePktLen = %d, want 42", udpBasePktLen)
	}
	if offUDPSrcPort != 34 {
		t.Fatalf("offUDPSrcPort = %d, want 34", offUDPSrcPort)
	}
	if offUDPDstPort != 36 {
		t.Fatalf("offUDPDstPort = %d, want 36", offUDPDstPort)
	}
	if offUDPLength != 38 {
		t.Fatalf("offUDPLength = %d, want 38", offUDPLength)
	}
	if offUDPChecksum != 40 {
		t.Fatalf("offUDPChecksum = %d, want 40", offUDPChecksum)
	}
	_ = s
}
