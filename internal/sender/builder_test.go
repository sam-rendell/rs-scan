package sender

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildSYN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1")

	pb, err := NewPacketBuilder(srcMAC, dstMAC, srcIP)
	if err != nil {
		t.Fatalf("NewPacketBuilder failed: %v", err)
	}

	dstIP := net.ParseIP("8.8.8.8")
	data, err := pb.BuildSYN(dstIP, 80)
	if err != nil {
		t.Fatalf("BuildSYN failed: %v", err)
	}

	// Decode to verify
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if !tcp.SYN {
			t.Error("Packet is not a SYN")
		}
		if tcp.DstPort != 80 {
			t.Errorf("Expected port 80, got %d", tcp.DstPort)
		}
	} else {
		t.Error("No TCP layer found")
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if !ip.DstIP.Equal(dstIP) {
			t.Errorf("Expected DstIP %s, got %s", dstIP, ip.DstIP)
		}
	} else {
		t.Error("No IPv4 layer found")
	}
}

func TestIPChecksum(t *testing.T) {
	// Known-good IP header (RFC 1071 example variant)
	// Version=4, IHL=5, TotalLen=44, TTL=64, Proto=TCP, SrcIP=10.0.0.1, DstIP=8.8.8.8
	hdr := [20]byte{
		0x45, 0x00, 0x00, 0x2C, // Version/IHL, DSCP, TotalLen=44
		0x00, 0x01, 0x40, 0x00, // Id=1, Flags=DF, FragOff=0
		0x40, 0x06, 0x00, 0x00, // TTL=64, Proto=TCP, Checksum=0 (to be computed)
		0x0A, 0x00, 0x00, 0x01, // SrcIP 10.0.0.1
		0x08, 0x08, 0x08, 0x08, // DstIP 8.8.8.8
	}
	cksum := ipChecksum(hdr[:])
	if cksum == 0 {
		t.Error("IP checksum should not be zero for non-zero header")
	}
	// Verify: recomputing with the checksum embedded should yield 0
	hdr[10] = byte(cksum >> 8)
	hdr[11] = byte(cksum)
	verify := ipChecksum(hdr[:])
	if verify != 0 {
		t.Errorf("IP checksum verification failed: got 0x%04x, want 0", verify)
	}
}

func TestTCPChecksum(t *testing.T) {
	srcIP := []byte{10, 0, 0, 1}
	dstIP := []byte{8, 8, 8, 8}
	// Minimal SYN segment: SrcPort=12345, DstPort=80, Seq=1, DataOff=6, SYN, Window=64240, MSS=1460
	seg := []byte{
		0x30, 0x39, 0x00, 0x50, // SrcPort=12345, DstPort=80
		0x00, 0x00, 0x00, 0x01, // Seq=1
		0x00, 0x00, 0x00, 0x00, // Ack=0
		0x60, 0x02, 0xFB, 0x10, // DataOff=6, SYN, Window=64240
		0x00, 0x00, 0x00, 0x00, // Checksum=0, Urgent=0
		0x02, 0x04, 0x05, 0xB4, // MSS option: 1460
	}
	cksum := tcpChecksum(srcIP, dstIP, seg)
	if cksum == 0 {
		t.Error("TCP checksum should not be zero")
	}
	// Embed and verify
	seg[16] = byte(cksum >> 8)
	seg[17] = byte(cksum)
	verify := tcpChecksum(srcIP, dstIP, seg)
	if verify != 0 {
		t.Errorf("TCP checksum verification failed: got 0x%04x, want 0", verify)
	}
}
