//go:build linux

package sender

import (
	"fmt"
	"time"

	"github.com/google/gopacket/afpacket"
	"golang.org/x/sys/unix"
)

func newPacketWriter(iface string) (packetWriter, error) {
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
	return handle, nil
}

// tunnelWriter uses AF_INET6 SOCK_RAW with IPV6_HDRINCL for non-Ethernet
// interfaces (GRE, SIT, IPIP, etc). AF_PACKET injection silently fails on
// these tunnel types because the kernel doesn't route the packets through the
// tunnel encapsulation. Using a raw socket lets the kernel handle routing and
// encapsulation correctly.
type tunnelWriter struct {
	fd6 int // AF_INET6 SOCK_RAW with IPV6_HDRINCL
	fd4 int // AF_INET SOCK_RAW with IP_HDRINCL (for IPv4 if needed)
}

const (
	_IPV6_HDRINCL   = 36 // not in x/sys/unix
	_SO_BINDTODEVICE = 25
)

func newTunnelWriter(iface string) (packetWriter, error) {
	// IPv6 raw socket with header-included mode
	fd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("AF_INET6 SOCK_RAW: %w", err)
	}
	if err := unix.SetsockoptInt(fd6, unix.IPPROTO_IPV6, _IPV6_HDRINCL, 1); err != nil {
		unix.Close(fd6)
		return nil, fmt.Errorf("IPV6_HDRINCL: %w", err)
	}
	// Bind to the tunnel interface
	if err := unix.BindToDevice(fd6, iface); err != nil {
		unix.Close(fd6)
		return nil, fmt.Errorf("SO_BINDTODEVICE (v6): %w", err)
	}

	// IPv4 raw socket (optional — best-effort, some tunnels are v6-only)
	fd4, _ := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if fd4 >= 0 {
		unix.SetsockoptInt(fd4, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		unix.BindToDevice(fd4, iface)
	}

	return &tunnelWriter{fd6: fd6, fd4: fd4}, nil
}

func (tw *tunnelWriter) WritePacketData(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if data[0]>>4 == 6 {
		// IPv6: extract destination from header bytes [24:40]
		if len(data) < 40 {
			return fmt.Errorf("IPv6 packet too short: %d", len(data))
		}
		var dst [16]byte
		copy(dst[:], data[24:40])
		sa6 := &unix.SockaddrInet6{Addr: dst}
		return unix.Sendto(tw.fd6, data, 0, sa6)
	}
	// IPv4: extract destination from header bytes [16:20]
	if tw.fd4 < 0 || len(data) < 20 {
		return fmt.Errorf("no IPv4 socket or packet too short")
	}
	sa4 := &unix.SockaddrInet4{Addr: [4]byte{data[16], data[17], data[18], data[19]}}
	return unix.Sendto(tw.fd4, data, 0, sa4)
}

func (tw *tunnelWriter) Close() {
	unix.Close(tw.fd6)
	if tw.fd4 >= 0 {
		unix.Close(tw.fd4)
	}
}
