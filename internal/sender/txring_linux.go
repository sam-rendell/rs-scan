//go:build linux

package sender

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TX_RING constants
const (
	tpStatusAvailable   = 0                // TP_STATUS_AVAILABLE (kernel done, slot free)
	tpStatusSendRequest = 1                // TP_STATUS_SEND_REQUEST (userspace requests send)
	tpStatusWrongFormat = 4                // TP_STATUS_WRONG_FORMAT

	txFrameSize   = 256        // TPACKET_ALIGN(TPACKET2_HDRLEN) + max packet
	txBlockSize   = 1 << 20    // 1MB per block
	txBlockNr     = 64         // 64 blocks = 64MB ring
	txFrameNr     = txBlockNr * txBlockSize / txFrameSize // total frames in ring
)

// tpacket2Hdr mirrors struct tpacket2_hdr (simplified, only fields we need).
type tpacket2Hdr struct {
	Status    uint32
	Len       uint32
	Snaplen   uint32
	Mac       uint16
	Net       uint16
	Sec       uint32
	Nsec      uint32
	VlanTCI   uint16
	VlanTPID  uint16
	_         [4]byte
}

const tpacket2HdrLen = 32 // sizeof(tpacket2_hdr)

// TXRingSender uses AF_PACKET TX_RING for zero-copy batched packet injection.
// Packets are written directly to mmap'd ring memory. A single sendto() flushes
// all pending frames — this is how masscan achieves 10M+ pps.
type TXRingSender struct {
	fd           int
	ring         []byte // mmap'd TX ring
	frameSize    int
	frameNr      int
	frameIdx     int // current write position in ring
	pending      int // frames written but not yet flushed
	writeOff     int // 0 for Ethernet, ethLen for TUN
	cookieSecret uint64
	ipID         uint16

	synTpl   [synPktLen]byte
	synPktV6 [synPktLenV6]byte // IPv6 SYN template
	hasV6    bool               // true if IPv6 template is configured
}

// NewTXRingSender creates a high-throughput sender using AF_PACKET TPACKET_V2 TX_RING.
func NewTXRingSender(iface string, srcMAC, dstMAC net.HardwareAddr, srcIP net.IP) (*TXRingSender, error) {
	// Open raw AF_PACKET socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}

	// Set TPACKET_V2 (V3 TX_RING is not supported on all kernels for TX)
	ver := 1 // TPACKET_V2
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, ver); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TPACKET_V2: %w", err)
	}

	// Set up TX_RING
	req := struct {
		BlockSize uint32
		BlockNr   uint32
		FrameSize uint32
		FrameNr   uint32
	}{
		BlockSize: txBlockSize,
		BlockNr:   txBlockNr,
		FrameSize: txFrameSize,
		FrameNr:   txFrameNr,
	}

	// PACKET_TX_RING = 13
	const PACKET_TX_RING = 13
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(unix.SOL_PACKET), uintptr(PACKET_TX_RING),
		uintptr(unsafe.Pointer(&req)), unsafe.Sizeof(req), 0)
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("PACKET_TX_RING: %w", errno)
	}

	// mmap the TX ring
	ringSize := int(txBlockSize * txBlockNr)
	ring, err := unix.Mmap(fd, 0, ringSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("mmap TX ring: %w", err)
	}

	// Resolve interface index and bind
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Munmap(ring)
		unix.Close(fd)
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	sa := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifc.Index,
	}
	if err := unix.Bind(fd, &sa); err != nil {
		unix.Munmap(ring)
		unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}

	// QDISC bypass
	unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_QDISC_BYPASS, 1)

	// Random secret
	b := make([]byte, 16)
	rand.Read(b)
	secret := binary.LittleEndian.Uint64(b[0:8])
	ipID := binary.LittleEndian.Uint16(b[8:10])

	ts := &TXRingSender{
		fd:           fd,
		ring:         ring,
		frameSize:    txFrameSize,
		frameNr:      txFrameNr,
		cookieSecret: secret,
		ipID:         ipID,
	}

	isTUN := len(srcMAC) == 0
	if isTUN {
		ts.writeOff = ethLen
	}

	// Build IPv4 SYN template (skipped for IPv6-only interfaces)
	if srcIP != nil {
		srcIP4 := srcIP.To4()
		if !isTUN {
			buildEthHeader(ts.synTpl[:], srcMAC, dstMAC)
		}
		buildIPv4Header(ts.synTpl[:], srcIP4, synTCPLen)
		ts.synTpl[offTCPDataOff] = 0xA0
		ts.synTpl[offTCPFlags] = 0x02
		binary.BigEndian.PutUint16(ts.synTpl[offTCPWindow:], 64240)
		o := tcpOff + 20
		ts.synTpl[o+0] = 2
		ts.synTpl[o+1] = 4
		ts.synTpl[o+2] = 0x05
		ts.synTpl[o+3] = 0xB4
		ts.synTpl[o+4] = 4
		ts.synTpl[o+5] = 2
		ts.synTpl[o+6] = 8
		ts.synTpl[o+7] = 10
		binary.BigEndian.PutUint32(ts.synTpl[o+8:], uint32(secret))
		ts.synTpl[o+16] = 1
		ts.synTpl[o+17] = 3
		ts.synTpl[o+18] = 3
		ts.synTpl[o+19] = 7
	}

	return ts, nil
}

// ConfigureIPv6 builds an IPv6 SYN template for dual-stack scanning.
// srcIPv6 must be a full 16-byte IPv6 address. Call after NewTXRingSender.
func (ts *TXRingSender) ConfigureIPv6(srcIPv6 [16]byte, srcMAC, dstMAC net.HardwareAddr) {
	isTUN := ts.writeOff == ethLen

	// Build IPv6 SYN template
	if !isTUN {
		buildEthHeaderV6(ts.synPktV6[:], srcMAC, dstMAC)
	}
	buildIPv6Header(ts.synPktV6[:], srcIPv6, 6, synTCPLen) // Next Header = TCP
	ts.synPktV6[offV6TCPDataOff] = 0xA0                    // Data Offset = 10 words (40 bytes)
	ts.synPktV6[offV6TCPFlags] = 0x02                      // SYN
	binary.BigEndian.PutUint16(ts.synPktV6[offV6TCPWindow:], 64240)

	// TCP options (same as IPv4 SYN)
	o := tcpOffV6 + 20
	ts.synPktV6[o+0] = 2
	ts.synPktV6[o+1] = 4
	ts.synPktV6[o+2] = 0x05
	ts.synPktV6[o+3] = 0xB4 // MSS 1460
	ts.synPktV6[o+4] = 4
	ts.synPktV6[o+5] = 2 // SACK
	ts.synPktV6[o+6] = 8
	ts.synPktV6[o+7] = 10 // Timestamps
	binary.BigEndian.PutUint32(ts.synPktV6[o+8:], uint32(ts.cookieSecret))
	ts.synPktV6[o+16] = 1 // NOP
	ts.synPktV6[o+17] = 3
	ts.synPktV6[o+18] = 3
	ts.synPktV6[o+19] = 7 // WScale=7

	ts.hasV6 = true
}

// GenerateCookie is identical to RingSender.GenerateCookie.
// dstIP is a [16]byte for dual IPv4/IPv6 support (Phase 1: IPv4 uses last 4 bytes).
func (ts *TXRingSender) GenerateCookie(dstIP [16]byte, dstPort uint16) uint32 {
	const prime32 = uint32(16777619)
	h := uint32(2166136261)
	h ^= uint32(ts.cookieSecret)
	h *= prime32
	h ^= uint32(ts.cookieSecret >> 32)
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

// QueueSYN writes a SYN packet into the next TX ring frame.
// Returns true if the ring is getting full and should be flushed.
// dstIP is a [16]byte: IPv4-mapped uses IPv4 template, otherwise IPv6.
func (ts *TXRingSender) QueueSYN(dstIP [16]byte, dstPort, srcPort uint16) bool {
	if !isIPv4Mapped(dstIP) && ts.hasV6 {
		return ts.queueSYNv6(dstIP, dstPort, srcPort)
	}

	// Find the frame slot in the mmap'd ring
	off := ts.frameIdx * ts.frameSize
	hdr := (*tpacket2Hdr)(unsafe.Pointer(&ts.ring[off]))

	// Wait for this slot to be available (kernel finished sending previous packet)
	// In practice with a large ring, this rarely blocks.
	for hdr.Status != tpStatusAvailable {
		// Slot still owned by kernel — flush pending and spin
		ts.flush()
		// Re-read after flush
		hdr = (*tpacket2Hdr)(unsafe.Pointer(&ts.ring[off]))
	}

	// Packet data starts after the tpacket2 header, aligned to TPACKET_ALIGNMENT (16 bytes)
	// For TPACKET_V2, the data offset is TPACKET2_HDRLEN = 32 bytes
	pktOff := off + tpacket2HdrLen
	pkt := ts.ring[pktOff : pktOff+synPktLen]

	// Copy template
	copy(pkt, ts.synTpl[:])

	// Patch fields
	ts.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], ts.ipID)
	// Patch DstIP (Phase 1: extract IPv4 from last 4 bytes)
	copy(pkt[offIPDstIP:offIPDstIP+4], dstIP[12:16])
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))
	binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offTCPDstPort:], dstPort)
	binary.BigEndian.PutUint32(pkt[offTCPSeq:], ts.GenerateCookie(dstIP, dstPort))
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:synPktLen]))

	// Set frame length and mark for sending
	pktLen := synPktLen - ts.writeOff
	hdr.Len = uint32(pktLen)
	hdr.Status = tpStatusSendRequest

	ts.frameIdx = (ts.frameIdx + 1) % ts.frameNr
	ts.pending++

	// Flush when batch is large enough
	return ts.pending >= BatchSize
}

// queueSYNv6 writes an IPv6 SYN packet into the next TX ring frame.
func (ts *TXRingSender) queueSYNv6(dstIP [16]byte, dstPort, srcPort uint16) bool {
	// Find the frame slot in the mmap'd ring
	off := ts.frameIdx * ts.frameSize
	hdr := (*tpacket2Hdr)(unsafe.Pointer(&ts.ring[off]))

	// Wait for this slot to be available
	for hdr.Status != tpStatusAvailable {
		ts.flush()
		hdr = (*tpacket2Hdr)(unsafe.Pointer(&ts.ring[off]))
	}

	// Packet data starts after the tpacket2 header
	pktOff := off + tpacket2HdrLen
	pkt := ts.ring[pktOff : pktOff+synPktLenV6]

	// Copy IPv6 template
	copy(pkt, ts.synPktV6[:])

	// Patch fields
	copy(pkt[offV6DstIP:offV6DstIP+16], dstIP[:])
	binary.BigEndian.PutUint16(pkt[offV6TCPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offV6TCPDstPort:], dstPort)
	binary.BigEndian.PutUint32(pkt[offV6TCPSeq:], ts.GenerateCookie(dstIP, dstPort))
	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offV6TCPChecksum:],
		transportChecksumV6(6, pkt[offV6SrcIP:offV6SrcIP+16], pkt[offV6DstIP:offV6DstIP+16], pkt[tcpOffV6:synPktLenV6]))

	// Set frame length and mark for sending
	pktLen := synPktLenV6 - ts.writeOff
	hdr.Len = uint32(pktLen)
	hdr.Status = tpStatusSendRequest

	ts.frameIdx = (ts.frameIdx + 1) % ts.frameNr
	ts.pending++

	// Flush when batch is large enough
	return ts.pending >= BatchSize
}

// Flush sends all pending frames via sendto().
func (ts *TXRingSender) Flush() (int, error) {
	n := ts.pending
	if n == 0 {
		return 0, nil
	}
	ts.flush()
	ts.pending = 0
	return n, nil
}

func (ts *TXRingSender) flush() {
	// sendto(fd, NULL, 0, 0, NULL, 0) kicks the TX ring
	unix.Syscall6(unix.SYS_SENDTO, uintptr(ts.fd), 0, 0, 0, 0, 0)
}

// Pending returns the number of frames waiting to be flushed.
func (ts *TXRingSender) Pending() int {
	return ts.pending
}

// Close releases the TX ring and socket.
func (ts *TXRingSender) Close() {
	unix.Munmap(ts.ring)
	unix.Close(ts.fd)
}
