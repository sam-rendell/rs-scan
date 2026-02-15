package banner

import (
	"net"
	"sync/atomic"
	"time"

	"rs_scan/internal/sender"
	"rs_scan/internal/stack"
)

// ipAddrToNetIP converts stack.IPAddr to net.IP.
// For IPv4 (bytes 10-11 are 0xFF), returns the last 4 bytes.
// Otherwise returns the full 16 bytes (IPv6).
func ipAddrToNetIP(addr stack.IPAddr) net.IP {
	if addr[10] == 0xFF && addr[11] == 0xFF {
		// IPv4-mapped address
		return net.IP(addr[12:16])
	}
	// IPv6
	return net.IP(addr[:])
}

// Responder drains the TXRing and sends response packets (ACKs, hello payloads, RSTs)
// via its own AF_PACKET TX socket. Runs as a dedicated goroutine.
type Responder struct {
	txRing  *TXRing
	sender  *sender.RingSender
	srcIP   net.IP
	running *int32
	done    chan struct{}
}

// NewResponder creates a response TX goroutine sender.
func NewResponder(iface string, srcMAC, dstMAC net.HardwareAddr, srcIP net.IP, txRing *TXRing, running *int32) (*Responder, error) {
	s, err := sender.NewRingSender(iface, srcMAC, dstMAC, srcIP)
	if err != nil {
		return nil, err
	}
	return &Responder{
		txRing:  txRing,
		sender:  s,
		srcIP:   srcIP,
		running: running,
		done:    make(chan struct{}),
	}, nil
}

// Run is the main loop. Call as a goroutine: go responder.Run()
// It batch-drains the TX ring and sends packets.
func (r *Responder) Run() {
	defer close(r.done)
	batch := make([]TXRequest, 256)

	for atomic.LoadInt32(r.running) == 1 {
		n := r.txRing.DrainBatch(batch, 256)
		if n == 0 {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		for i := 0; i < n; i++ {
			req := &batch[i]
			dstIP := ipAddrToNetIP(req.DstIP)

			switch {
			case req.Flags == FlagACK && req.Payload == nil:
				// Bare ACK
				r.sender.SendACK(dstIP, int(req.DstPort), int(req.SrcPort), req.Seq, req.Ack)

			case req.Flags == FlagRST:
				// RST — use SendRST (we'll add this to sender)
				r.sender.SendRST(dstIP, int(req.DstPort), int(req.SrcPort), req.Seq)

			case req.Flags == FlagPSHACK && req.Payload != nil:
				// PSH+ACK with payload (hello, negotiate reply)
				r.sender.SendData(dstIP, int(req.DstPort), int(req.SrcPort), req.Seq, req.Ack, req.Payload)

			default:
				// Fallback: send as ACK
				r.sender.SendACK(dstIP, int(req.DstPort), int(req.SrcPort), req.Seq, req.Ack)
			}
		}
	}
}

// ConfigureIPv6 enables IPv6 support on the responder's internal sender.
func (r *Responder) ConfigureIPv6(srcIPv6 [16]byte, srcMAC, dstMAC net.HardwareAddr) {
	r.sender.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)
}

// Close waits for Run() to exit, then releases the underlying AF_PACKET handle.
func (r *Responder) Close() {
	<-r.done
	r.sender.Close()
}
