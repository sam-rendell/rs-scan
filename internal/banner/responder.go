package banner

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"rs_scan/internal/sender"
)

// Responder drains the TXRing and sends response packets (ACKs, hello payloads, RSTs)
// via its own AF_PACKET TX socket. Runs as a dedicated goroutine.
type Responder struct {
	txRing  *TXRing
	sender  *sender.RingSender
	srcIP   net.IP
	running *int32
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
	}, nil
}

// Run is the main loop. Call as a goroutine: go responder.Run()
// It batch-drains the TX ring and sends packets.
func (r *Responder) Run() {
	batch := make([]TXRequest, 256)

	for atomic.LoadInt32(r.running) == 1 {
		n := r.txRing.DrainBatch(batch, 256)
		if n == 0 {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		for i := 0; i < n; i++ {
			req := &batch[i]
			dstIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(dstIP, req.DstIP)

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

// Close releases the underlying AF_PACKET handle.
func (r *Responder) Close() {
	r.sender.Close()
}
