//go:build darwin

package receiver

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// pcapHandle wraps *pcap.Handle to implement CaptureHandle.
type pcapHandle struct {
	h *pcap.Handle
}

func (p *pcapHandle) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	return p.h.ReadPacketData()
}

func (p *pcapHandle) Close() {
	p.h.Close()
}

// NewListener creates a pcap capture handle (macOS/BPF).
func NewListener(iface string) (*Listener, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap init failed: %w", err)
	}

	return &Listener{Handle: &pcapHandle{h: handle}}, nil
}

// NewTunnelListener on darwin is the same as NewListener (pcap handles all interfaces).
func NewTunnelListener(iface string) (*Listener, error) {
	return NewListener(iface)
}

func (l *Listener) SetBPF(iface, filter string) error {
	h := l.Handle.(*pcapHandle)
	return h.h.SetBPFFilter(filter)
}

// SocketStats returns pcap capture statistics.
func (l *Listener) SocketStats() (received, dropped uint64) {
	h := l.Handle.(*pcapHandle)
	stats, err := h.h.Stats()
	if err != nil {
		return 0, 0
	}
	return uint64(stats.PacketsReceived), uint64(stats.PacketsDropped)
}
