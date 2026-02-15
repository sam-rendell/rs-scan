//go:build darwin

package sender

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func newPacketWriter(iface string) (packetWriter, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap handle: %w", err)
	}
	return handle, nil
}

// newTunnelWriter is a no-op on darwin — TUN injection uses pcap.
func newTunnelWriter(iface string) (packetWriter, error) {
	return newPacketWriter(iface)
}
