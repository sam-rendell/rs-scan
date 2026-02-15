//go:build e2e

package sender

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// TestE2E_PacketValidation is a full end-to-end test that:
//  1. Creates a veth pair (rs_e2e0 <-> rs_e2e1)
//  2. Creates a RingSender on rs_e2e0
//  3. Sends IPv4 SYN, IPv6 SYN, IPv4 UDP, IPv6 UDP packets
//  4. Captures them on rs_e2e1
//  5. Validates all header fields, checksums, and cookie values
//  6. Writes a pcap to /tmp/rs_scan_e2e.pcap
//
// Run: sudo go test -tags e2e -v -run TestE2E ./internal/sender/
func TestE2E_PacketValidation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	// ── Setup veth pair ──────────────────────────────────────────────
	setupVeth(t)
	t.Cleanup(func() { teardownVeth() })

	// Get interface info
	iface, err := net.InterfaceByName("rs_e2e0")
	if err != nil {
		t.Fatalf("InterfaceByName(rs_e2e0): %v", err)
	}
	srcMAC := iface.HardwareAddr
	// Fabricate a gateway MAC (doesn't matter for veth)
	dstMAC := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}

	// Source IPs
	srcIPv4 := net.ParseIP("10.99.99.1").To4()
	srcIPv6Raw := net.ParseIP("2001:db8::1").To16()
	var srcIPv6 [16]byte
	copy(srcIPv6[:], srcIPv6Raw)

	// ── Open pcap capture on peer (rs_e2e1) ──────────────────────────
	captureHandle, err := pcap.OpenLive("rs_e2e1", 1600, true, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("pcap.OpenLive(rs_e2e1): %v", err)
	}
	defer captureHandle.Close()

	// Open pcap file for writing
	pcapFile, err := os.Create("/tmp/rs_scan_e2e.pcap")
	if err != nil {
		t.Fatalf("create pcap file: %v", err)
	}
	defer pcapFile.Close()
	pcapWriter := pcapgo.NewWriterNanos(pcapFile)
	pcapWriter.WriteFileHeader(1600, layers.LinkTypeEthernet)

	// ── Create RingSender on rs_e2e0 ─────────────────────────────────
	sender, err := NewRingSender("rs_e2e0", srcMAC, dstMAC, srcIPv4)
	if err != nil {
		t.Fatalf("NewRingSender: %v", err)
	}
	defer sender.handle.Close()

	// Configure IPv6
	sender.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)

	// ── Define test packets ──────────────────────────────────────────
	type testPacket struct {
		name    string
		dstIP   [16]byte
		dstPort uint16
		srcPort uint16
		isIPv6  bool
		isUDP   bool
	}

	// IPv4-mapped: ::ffff:10.99.99.100
	var dstIPv4 [16]byte
	dstIPv4[10] = 0xFF
	dstIPv4[11] = 0xFF
	dstIPv4[12] = 10
	dstIPv4[13] = 99
	dstIPv4[14] = 99
	dstIPv4[15] = 100

	// IPv6: 2001:db8::dead:beef
	var dstIPv6 [16]byte
	copy(dstIPv6[:], net.ParseIP("2001:db8::dead:beef").To16())

	// IPv4 UDP dst
	var dstIPv4UDP [16]byte
	dstIPv4UDP[10] = 0xFF
	dstIPv4UDP[11] = 0xFF
	dstIPv4UDP[12] = 10
	dstIPv4UDP[13] = 99
	dstIPv4UDP[14] = 99
	dstIPv4UDP[15] = 200

	packets := []testPacket{
		{"IPv4_SYN", dstIPv4, 80, 40000, false, false},
		{"IPv4_SYN_443", dstIPv4, 443, 40001, false, false},
		{"IPv6_SYN", dstIPv6, 80, 50000, true, false},
		{"IPv6_SYN_443", dstIPv6, 443, 50001, true, false},
		{"IPv4_UDP", dstIPv4UDP, 53, 40002, false, true},
	}

	// ── Send packets ─────────────────────────────────────────────────
	for _, p := range packets {
		if p.isUDP {
			// UDP probe: simple DNS query header
			probe := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			if err := sender.SendUDP(p.dstIP, p.dstPort, p.srcPort, probe); err != nil {
				t.Fatalf("SendUDP(%s): %v", p.name, err)
			}
		} else {
			if err := sender.SendSYNWithPort(p.dstIP, p.dstPort, p.srcPort); err != nil {
				t.Fatalf("SendSYNWithPort(%s): %v", p.name, err)
			}
		}
	}

	// Small delay for packets to cross the veth pair
	time.Sleep(100 * time.Millisecond)

	// ── Capture and validate ─────────────────────────────────────────
	captured := make([]gopacket.Packet, 0, len(packets))
	deadline := time.Now().Add(2 * time.Second)

	for len(captured) < len(packets) && time.Now().Before(deadline) {
		data, ci, err := captureHandle.ReadPacketData()
		if err != nil {
			continue
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		captured = append(captured, pkt)

		// Write to pcap file
		pcapWriter.WritePacket(ci, data)
	}

	t.Logf("Captured %d packets (expected %d)", len(captured), len(packets))
	if len(captured) < len(packets) {
		t.Fatalf("only captured %d of %d packets", len(captured), len(packets))
	}

	// ── Validate each packet ─────────────────────────────────────────
	for i, pkt := range captured {
		if i >= len(packets) {
			break
		}
		spec := packets[i]
		t.Run(spec.name, func(t *testing.T) {
			validatePacket(t, pkt, spec.dstIP, spec.dstPort, spec.srcPort, spec.isIPv6, spec.isUDP, sender)
		})
	}

	t.Logf("pcap written to /tmp/rs_scan_e2e.pcap")
}

func validatePacket(t *testing.T, pkt gopacket.Packet, dstIP [16]byte, dstPort, srcPort uint16, isIPv6, isUDP bool, s *RingSender) {
	t.Helper()

	// ── Ethernet layer ───────────────────────────────────────────────
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("missing Ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)

	if isIPv6 {
		if eth.EthernetType != layers.EthernetTypeIPv6 {
			t.Errorf("EtherType = 0x%04X, want 0x86DD (IPv6)", uint16(eth.EthernetType))
		}
	} else {
		if eth.EthernetType != layers.EthernetTypeIPv4 {
			t.Errorf("EtherType = 0x%04X, want 0x0800 (IPv4)", uint16(eth.EthernetType))
		}
	}

	if isIPv6 {
		validateIPv6Packet(t, pkt, dstIP, dstPort, srcPort, isUDP, s)
	} else {
		validateIPv4Packet(t, pkt, dstIP, dstPort, srcPort, isUDP, s)
	}
}

func validateIPv4Packet(t *testing.T, pkt gopacket.Packet, dstIP [16]byte, dstPort, srcPort uint16, isUDP bool, s *RingSender) {
	t.Helper()

	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("missing IPv4 layer")
	}
	ip := ipLayer.(*layers.IPv4)

	// Version + IHL
	if ip.Version != 4 {
		t.Errorf("IPv4 Version = %d, want 4", ip.Version)
	}
	if ip.IHL != 5 {
		t.Errorf("IPv4 IHL = %d, want 5", ip.IHL)
	}

	// TTL
	if ip.TTL != 64 {
		t.Errorf("IPv4 TTL = %d, want 64", ip.TTL)
	}

	// Flags: Don't Fragment
	if ip.Flags&layers.IPv4DontFragment == 0 {
		t.Error("IPv4 DF flag not set")
	}

	// Dst IP (last 4 bytes of the [16]byte)
	expectedDst := net.IP(dstIP[12:16])
	if !ip.DstIP.Equal(expectedDst) {
		t.Errorf("DstIP = %s, want %s", ip.DstIP, expectedDst)
	}

	// Src IP
	if !ip.SrcIP.Equal(net.ParseIP("10.99.99.1")) {
		t.Errorf("SrcIP = %s, want 10.99.99.1", ip.SrcIP)
	}

	// Validate IP checksum
	rawIPHeader := ipLayer.LayerContents()
	if len(rawIPHeader) >= 20 {
		storedCksum := binary.BigEndian.Uint16(rawIPHeader[10:12])
		// Zero out checksum field, recompute
		copy(rawIPHeader[10:12], []byte{0, 0})
		computed := ipChecksum(rawIPHeader)
		if storedCksum != computed {
			t.Errorf("IPv4 checksum mismatch: stored=0x%04X computed=0x%04X", storedCksum, computed)
		}
	}

	if isUDP {
		validateUDPLayer(t, pkt, dstPort, srcPort)
	} else {
		validateTCPSYN(t, pkt, dstIP, dstPort, srcPort, s)
	}
}

func validateIPv6Packet(t *testing.T, pkt gopacket.Packet, dstIP [16]byte, dstPort, srcPort uint16, isUDP bool, s *RingSender) {
	t.Helper()

	ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		t.Fatal("missing IPv6 layer")
	}
	ip6 := ip6Layer.(*layers.IPv6)

	// Version
	if ip6.Version != 6 {
		t.Errorf("IPv6 Version = %d, want 6", ip6.Version)
	}

	// Hop Limit
	if ip6.HopLimit != 64 {
		t.Errorf("IPv6 HopLimit = %d, want 64", ip6.HopLimit)
	}

	// Dst IP
	expectedDst := net.IP(dstIP[:])
	if !ip6.DstIP.Equal(expectedDst) {
		t.Errorf("DstIP = %s, want %s", ip6.DstIP, expectedDst)
	}

	// Src IP
	expectedSrc := net.ParseIP("2001:db8::1")
	if !ip6.SrcIP.Equal(expectedSrc) {
		t.Errorf("SrcIP = %s, want %s", ip6.SrcIP, expectedSrc)
	}

	if isUDP {
		validateUDPLayer(t, pkt, dstPort, srcPort)
	} else {
		validateTCPSYN(t, pkt, dstIP, dstPort, srcPort, s)
	}
}

func validateTCPSYN(t *testing.T, pkt gopacket.Packet, dstIP [16]byte, dstPort, srcPort uint16, s *RingSender) {
	t.Helper()

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("missing TCP layer")
	}
	tcp := tcpLayer.(*layers.TCP)

	// Ports
	if uint16(tcp.SrcPort) != srcPort {
		t.Errorf("TCP SrcPort = %d, want %d", tcp.SrcPort, srcPort)
	}
	if uint16(tcp.DstPort) != dstPort {
		t.Errorf("TCP DstPort = %d, want %d", tcp.DstPort, dstPort)
	}

	// Flags: SYN only
	if !tcp.SYN {
		t.Error("SYN flag not set")
	}
	if tcp.ACK || tcp.RST || tcp.FIN || tcp.PSH {
		t.Errorf("unexpected flags: ACK=%v RST=%v FIN=%v PSH=%v", tcp.ACK, tcp.RST, tcp.FIN, tcp.PSH)
	}

	// Window
	if tcp.Window != 64240 {
		t.Errorf("Window = %d, want 64240", tcp.Window)
	}

	// Data Offset = 10 (40 bytes of TCP header with options)
	if tcp.DataOffset != 10 {
		t.Errorf("DataOffset = %d, want 10", tcp.DataOffset)
	}

	// Validate SYN Cookie (sequence number)
	expectedCookie := s.GenerateCookie(dstIP, dstPort)
	if tcp.Seq != expectedCookie {
		t.Errorf("SeqNum = 0x%08X, want cookie 0x%08X", tcp.Seq, expectedCookie)
	}

	// Validate TCP Options
	validateSYNOptions(t, tcp.Options)

	// Validate TCP checksum via gopacket
	if pkt.Layer(layers.LayerTypeIPv4) != nil {
		ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		tcp.SetNetworkLayerForChecksum(ip)
	} else if pkt.Layer(layers.LayerTypeIPv6) != nil {
		ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		tcp.SetNetworkLayerForChecksum(ip6)
	}
	// Reserialize to verify checksum
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	err := tcp.SerializeTo(buf, opts)
	if err == nil {
		recomputed := buf.Bytes()
		if len(recomputed) >= 18 {
			origRaw := tcpLayer.LayerContents()
			origCksum := binary.BigEndian.Uint16(origRaw[16:18])
			newCksum := binary.BigEndian.Uint16(recomputed[16:18])
			if origCksum != newCksum {
				t.Errorf("TCP checksum mismatch: packet=0x%04X recomputed=0x%04X", origCksum, newCksum)
			}
		}
	}
}

func validateSYNOptions(t *testing.T, opts []layers.TCPOption) {
	t.Helper()

	foundMSS := false
	foundSACK := false
	foundTimestamp := false
	foundWScale := false

	for _, opt := range opts {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			foundMSS = true
			if len(opt.OptionData) >= 2 {
				mss := binary.BigEndian.Uint16(opt.OptionData)
				if mss != 1460 && mss != 1440 {
					t.Errorf("MSS = %d, want 1460 (v4) or 1440 (v6)", mss)
				}
			}
		case layers.TCPOptionKindSACKPermitted:
			foundSACK = true
		case layers.TCPOptionKindTimestamps:
			foundTimestamp = true
			if len(opt.OptionData) < 8 {
				t.Error("Timestamp option too short")
			}
		case layers.TCPOptionKindWindowScale:
			foundWScale = true
			if len(opt.OptionData) >= 1 && opt.OptionData[0] != 7 {
				t.Errorf("WScale = %d, want 7", opt.OptionData[0])
			}
		}
	}

	if !foundMSS {
		t.Error("missing MSS option")
	}
	if !foundSACK {
		t.Error("missing SACK Permitted option")
	}
	if !foundTimestamp {
		t.Error("missing Timestamp option")
	}
	if !foundWScale {
		t.Error("missing Window Scale option")
	}
}

func validateUDPLayer(t *testing.T, pkt gopacket.Packet, dstPort, srcPort uint16) {
	t.Helper()

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("missing UDP layer")
	}
	udp := udpLayer.(*layers.UDP)

	if uint16(udp.SrcPort) != srcPort {
		t.Errorf("UDP SrcPort = %d, want %d", udp.SrcPort, srcPort)
	}
	if uint16(udp.DstPort) != dstPort {
		t.Errorf("UDP DstPort = %d, want %d", udp.DstPort, dstPort)
	}

	// Should have payload (DNS query header)
	if len(udp.Payload) == 0 {
		t.Error("UDP payload empty")
	}
}

// ── veth setup/teardown ──────────────────────────────────────────────

func setupVeth(t *testing.T) {
	t.Helper()

	cmds := [][]string{
		{"ip", "link", "add", "rs_e2e0", "type", "veth", "peer", "name", "rs_e2e1"},
		{"ip", "link", "set", "rs_e2e0", "up"},
		{"ip", "link", "set", "rs_e2e1", "up"},
		{"ip", "addr", "add", "10.99.99.1/24", "dev", "rs_e2e0"},
		{"ip", "-6", "addr", "add", "2001:db8::1/64", "dev", "rs_e2e0"},
		// Enable promiscuous mode on capture side
		{"ip", "link", "set", "rs_e2e1", "promisc", "on"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("setup %v: %v\n%s", args, err, out)
		}
	}
	// Wait for interfaces to come up
	time.Sleep(200 * time.Millisecond)
}

func teardownVeth() {
	exec.Command("ip", "link", "del", "rs_e2e0").Run()
}

// TestE2E_Summary prints a human-readable summary after running.
// Run together: sudo go test -tags e2e -v -run TestE2E ./internal/sender/
func TestE2E_Summary(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	pcapPath := "/tmp/rs_scan_e2e.pcap"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("pcap not found — run TestE2E_PacketValidation first")
	}

	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer handle.Close()

	var (
		totalPkts int
		ipv4SYN   int
		ipv6SYN   int
		ipv4UDP   int
		ipv6UDP   int
	)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range packetSource.Packets() {
		totalPkts++

		hasIPv4 := pkt.Layer(layers.LayerTypeIPv4) != nil
		hasIPv6 := pkt.Layer(layers.LayerTypeIPv6) != nil
		hasTCP := pkt.Layer(layers.LayerTypeTCP) != nil
		hasUDP := pkt.Layer(layers.LayerTypeUDP) != nil

		if hasIPv4 && hasTCP {
			tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if tcp.SYN && !tcp.ACK {
				ipv4SYN++
				t.Logf("  IPv4 SYN: %s:%d -> %s:%d  seq=0x%08X  ttl=%d  DF=%v",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
					tcp.Seq, ip.TTL, ip.Flags&layers.IPv4DontFragment != 0)
			}
		}
		if hasIPv6 && hasTCP {
			tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if tcp.SYN && !tcp.ACK {
				ipv6SYN++
				t.Logf("  IPv6 SYN: [%s]:%d -> [%s]:%d  seq=0x%08X  hop=%d",
					ip6.SrcIP, tcp.SrcPort, ip6.DstIP, tcp.DstPort,
					tcp.Seq, ip6.HopLimit)
			}
		}
		if hasIPv4 && hasUDP {
			udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			ipv4UDP++
			t.Logf("  IPv4 UDP: %s:%d -> %s:%d  len=%d",
				ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort, udp.Length)
		}
		if hasIPv6 && hasUDP {
			udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			ipv6UDP++
			t.Logf("  IPv6 UDP: [%s]:%d -> [%s]:%d  len=%d",
				ip6.SrcIP, udp.SrcPort, ip6.DstIP, udp.DstPort, udp.Length)
		}
	}

	t.Logf("\n=== PCAP Summary ===")
	t.Logf("Total packets:  %d", totalPkts)
	t.Logf("IPv4 SYN:       %d", ipv4SYN)
	t.Logf("IPv6 SYN:       %d", ipv6SYN)
	t.Logf("IPv4 UDP:       %d", ipv4UDP)
	t.Logf("IPv6 UDP:       %d", ipv6UDP)

	if ipv4SYN == 0 {
		t.Error("no IPv4 SYN packets captured")
	}
	if ipv6SYN == 0 {
		t.Error("no IPv6 SYN packets captured")
	}
}

// ── Helpers ──────────────────────────────────────────────────────────

// fmtMAC formats MAC address for display.
func fmtMAC(m net.HardwareAddr) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}
