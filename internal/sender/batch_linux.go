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

// BatchSize is the number of packets sent per sendmmsg() syscall.
const BatchSize = 256

// mmsghdr mirrors C struct mmsghdr for sendmmsg.
type mmsghdr struct {
	Hdr    unix.Msghdr
	MsgLen uint32
	_      [4]byte // padding on amd64
}

// BatchSender sends SYN packets in batches using sendmmsg() to amortize
// syscall overhead. One sendmmsg() call sends up to BatchSize packets.
type BatchSender struct {
	fd           int
	writeOff     int // 0 for Ethernet, ethLen for TUN
	cookieSecret uint64
	ipID         uint16
	hasV6        bool // true if IPv6 template is configured

	// Pre-built template
	synTpl [synPktLen]byte

	// Batch buffers — pre-allocated, reused every flush
	pktBuf [BatchSize][synPktLen]byte
	iovecs [BatchSize]unix.Iovec
	msgs   [BatchSize]mmsghdr
	count  int
}

// NewBatchSender creates a high-throughput sender using raw AF_PACKET + sendmmsg.
func NewBatchSender(iface string, srcMAC, dstMAC net.HardwareAddr, srcIP net.IP) (*BatchSender, error) {
	// Open raw AF_PACKET socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}

	// Resolve interface index
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	// Bind to interface
	sa := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifc.Index,
	}
	if err := unix.Bind(fd, &sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET: %w", err)
	}

	// Increase socket send buffer to 16MB
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 16*1024*1024)

	// Set QDISC bypass to skip TC layer (reduces per-packet overhead)
	unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_QDISC_BYPASS, 1)

	// Random secret and starting IP.Id
	b := make([]byte, 16)
	rand.Read(b)

	secret := binary.LittleEndian.Uint64(b[0:8])
	ipID := binary.LittleEndian.Uint16(b[8:10])

	bs := &BatchSender{
		fd:           fd,
		cookieSecret: secret,
		ipID:         ipID,
	}

	isTUN := len(srcMAC) == 0
	if isTUN {
		bs.writeOff = ethLen
	}

	// Build IPv4 SYN template (skipped for IPv6-only interfaces)
	if srcIP != nil {
		srcIP4 := srcIP.To4()
		if !isTUN {
			buildEthHeader(bs.synTpl[:], srcMAC, dstMAC)
		}
		buildIPv4Header(bs.synTpl[:], srcIP4, synTCPLen)
		bs.synTpl[offTCPDataOff] = 0xA0 // Data Offset = 10 words (40 bytes)
		bs.synTpl[offTCPFlags] = 0x02   // SYN
		binary.BigEndian.PutUint16(bs.synTpl[offTCPWindow:], 64240)
		o := tcpOff + 20
		bs.synTpl[o+0] = 2
		bs.synTpl[o+1] = 4
		bs.synTpl[o+2] = 0x05
		bs.synTpl[o+3] = 0xB4
		bs.synTpl[o+4] = 4
		bs.synTpl[o+5] = 2
		bs.synTpl[o+6] = 8
		bs.synTpl[o+7] = 10
		binary.BigEndian.PutUint32(bs.synTpl[o+8:], uint32(secret))
		bs.synTpl[o+16] = 1
		bs.synTpl[o+17] = 3
		bs.synTpl[o+18] = 3
		bs.synTpl[o+19] = 7
	}

	// Pre-wire iovec → pktBuf and msgs → iovec
	for i := range BatchSize {
		bs.iovecs[i].Base = &bs.pktBuf[i][bs.writeOff]
		bs.iovecs[i].Len = uint64(synPktLen - bs.writeOff)
		bs.msgs[i].Hdr.Iov = &bs.iovecs[i]
		bs.msgs[i].Hdr.Iovlen = 1
		// Copy template into each slot
		copy(bs.pktBuf[i][:], bs.synTpl[:])
	}

	return bs, nil
}

// ConfigureIPv6 sets up IPv6 packet template for batching.
// Phase 2: placeholder — sets hasV6 flag but IPv6 batching optimization is deferred.
// IPv6 SYN packets are 94 bytes vs 74 bytes for IPv4, requiring separate batch buffers.
func (bs *BatchSender) ConfigureIPv6(srcIPv6 [16]byte, srcMAC, dstMAC net.HardwareAddr) {
	bs.hasV6 = true
	// TODO Phase 3+: Build IPv6 SYN template, allocate separate v6 packet buffers
	// For now, IPv6 packets will bypass batching in QueueSYN (fall back to sendto)
}

// GenerateCookie creates a stateless SYN Cookie (same as RingSender).
// dstIP is a [16]byte for dual IPv4/IPv6 support (Phase 1: IPv4 uses last 4 bytes).
func (bs *BatchSender) GenerateCookie(dstIP [16]byte, dstPort uint16) uint32 {
	const prime32 = uint32(16777619)
	h := uint32(2166136261)
	h ^= uint32(bs.cookieSecret)
	h *= prime32
	h ^= uint32(bs.cookieSecret >> 32)
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

// QueueSYN builds a SYN packet into the batch buffer. Returns true if the
// batch is full and must be flushed before queuing more.
// dstIP is a [16]byte (Phase 1: IPv4 uses last 4 bytes at [12:16]).
func (bs *BatchSender) QueueSYN(dstIP [16]byte, dstPort, srcPort uint16) bool {
	i := bs.count
	pkt := &bs.pktBuf[i]

	// Patch IP.Id
	bs.ipID++
	binary.BigEndian.PutUint16(pkt[offIPId:], bs.ipID)

	// Patch DstIP (Phase 1: extract IPv4 from last 4 bytes)
	copy(pkt[offIPDstIP:offIPDstIP+4], dstIP[12:16])

	// Recompute IP checksum
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))

	// Patch TCP fields
	binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], srcPort)
	binary.BigEndian.PutUint16(pkt[offTCPDstPort:], dstPort)
	binary.BigEndian.PutUint32(pkt[offTCPSeq:], bs.GenerateCookie(dstIP, dstPort))

	// Recompute TCP checksum
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
	binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
		tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:synPktLen]))

	bs.count++
	return bs.count >= BatchSize
}

// Flush sends all queued packets with a single sendmmsg() syscall.
func (bs *BatchSender) Flush() (int, error) {
	if bs.count == 0 {
		return 0, nil
	}
	n := bs.count
	bs.count = 0

	sent, err := sendmmsg(bs.fd, bs.msgs[:n])
	return sent, err
}

// Close releases the AF_PACKET socket.
func (bs *BatchSender) Close() {
	unix.Close(bs.fd)
}

// Count returns the number of packets currently queued.
func (bs *BatchSender) Count() int {
	return bs.count
}

// sendmmsg wraps the sendmmsg(2) syscall.
func sendmmsg(fd int, msgs []mmsghdr) (int, error) {
	n, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		0, // flags
		0,
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
