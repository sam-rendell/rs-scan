package receiver

import (
	"fmt"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// Listener handles raw packet capture using AF_PACKET Ring Buffer.
type Listener struct {
	Handle *afpacket.TPacket
}

// NewListener creates a page-aligned TPacket V2 handle.
func NewListener(iface string) (*Listener, error) {
	// Stability Fix: BlockSize must be multiple of PageSize (4096).
	// BlockSize: 1MB, FrameSize: 2048, NumBlocks: 128 (128MB total)
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

	return &Listener{Handle: handle}, nil
}

func (l *Listener) SetBPF(iface, filter string) error {
	pcapHandle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil { return err }
	defer pcapHandle.Close()

	bpfInsts, err := pcapHandle.CompileBPFFilter(filter)
	if err != nil { return err }

	raw := make([]bpf.RawInstruction, len(bpfInsts))
	for i, ins := range bpfInsts {
		raw[i] = bpf.RawInstruction{Op: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	return l.Handle.SetBPF(raw)
}

// SocketStats returns AF_PACKET ring buffer statistics (packets received, dropped).
func (l *Listener) SocketStats() (received, dropped uint64) {
	_, stats, err := l.Handle.SocketStats()
	if err != nil {
		return 0, 0
	}
	return uint64(stats.Packets()), uint64(stats.Drops())
}

func (l *Listener) Close() {
	l.Handle.Close()
}
