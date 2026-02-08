package sender

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketBuilder creates raw packets efficiently.
type PacketBuilder struct {
	eth  layers.Ethernet
	ip4  layers.IPv4
	tcp  layers.TCP
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// NewPacketBuilder initializes a builder with static template data.
func NewPacketBuilder(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP) (*PacketBuilder, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := layers.IPv4{
		SrcIP:    srcIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(0), // Placeholder
		DstPort: layers.TCPPort(0), // Placeholder
		SYN:     true,
		Window:  1024,
	}

	return &PacketBuilder{
		eth:  eth,
		ip4:  ip4,
		tcp:  tcp,
		opts: opts,
		buf:  buf,
	}, nil
}

// BuildSYN constructs a SYN packet for the given target.
// Returns a byte slice. Warning: The slice is valid only until the next Build call.
func (pb *PacketBuilder) BuildSYN(dstIP net.IP, dstPort int) ([]byte, error) {
	pb.buf.Clear()

	// Update mutable fields
	pb.ip4.DstIP = dstIP
	pb.tcp.DstPort = layers.TCPPort(dstPort)
	// Randomize SrcPort slightly or keep static? Static for now, controlled by manager.
	// In a real scan, we might want to vary this or use the tuple hash.
	pb.tcp.SrcPort = layers.TCPPort(12345) 
	pb.tcp.SetNetworkLayerForChecksum(&pb.ip4)

	// Serialize
	err := gopacket.SerializeLayers(pb.buf, pb.opts,
		&pb.eth,
		&pb.ip4,
		&pb.tcp,
	)
	if err != nil {
		return nil, err
	}

	return pb.buf.Bytes(), nil
}
