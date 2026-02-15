//go:build linux

package receiver

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// afpacketHandle wraps *afpacket.TPacket to implement CaptureHandle.
type afpacketHandle struct {
	tp *afpacket.TPacket
}

func (h *afpacketHandle) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	return h.tp.ZeroCopyReadPacketData()
}

func (h *afpacketHandle) Close() {
	h.tp.Close()
}

// pcapHandle wraps *pcap.Handle for tunnel interfaces where AF_PACKET doesn't work.
type pcapHandle struct {
	h *pcap.Handle
}

func (h *pcapHandle) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	return h.h.ZeroCopyReadPacketData()
}

func (h *pcapHandle) Close() {
	h.h.Close()
}

// NewListener creates a page-aligned TPacket V2 handle (AF_PACKET, best for Ethernet).
func NewListener(iface string) (*Listener, error) {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(2048),
		afpacket.OptBlockSize(1024*1024),
		afpacket.OptNumBlocks(128),
		afpacket.OptPollTimeout(1*time.Millisecond),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion2),
	)
	if err != nil {
		return nil, fmt.Errorf("afpacket init failed: %w", err)
	}

	return &Listener{Handle: &afpacketHandle{tp: handle}}, nil
}

// NewTunnelListener creates a pcap-based listener for tunnel interfaces (GRE, SIT, etc).
// AF_PACKET cannot reliably capture on these interface types; pcap handles cooked
// capture (LINUX_SLL) correctly.
func NewTunnelListener(iface string) (*Listener, error) {
	handle, err := pcap.OpenLive(iface, 2048, true, 1*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open failed on %s: %w", iface, err)
	}
	return &Listener{Handle: &pcapHandle{h: handle}, UseSLL: true}, nil
}

func (l *Listener) SetBPF(iface, filter string) error {
	switch h := l.Handle.(type) {
	case *afpacketHandle:
		pcapHandle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
		if err != nil {
			return err
		}
		defer pcapHandle.Close()

		bpfInsts, err := pcapHandle.CompileBPFFilter(filter)
		if err != nil {
			return err
		}

		raw := make([]bpf.RawInstruction, len(bpfInsts))
		for i, ins := range bpfInsts {
			raw[i] = bpf.RawInstruction{Op: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		return h.tp.SetBPF(raw)

	case *pcapHandle:
		return h.h.SetBPFFilter(filter)

	default:
		return fmt.Errorf("unsupported handle type for BPF")
	}
}

// SocketStats returns AF_PACKET ring buffer statistics (packets received, dropped).
func (l *Listener) SocketStats() (received, dropped uint64) {
	switch h := l.Handle.(type) {
	case *afpacketHandle:
		_, stats, err := h.tp.SocketStats()
		if err != nil {
			return 0, 0
		}
		return uint64(stats.Packets()), uint64(stats.Drops())
	default:
		return 0, 0
	}
}
