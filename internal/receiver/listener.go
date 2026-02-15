package receiver

import "github.com/google/gopacket"

// CaptureHandle abstracts AF_PACKET (linux) vs pcap (darwin).
type CaptureHandle interface {
	ReadPacket() ([]byte, gopacket.CaptureInfo, error)
	Close()
}

// Listener handles raw packet capture.
type Listener struct {
	Handle CaptureHandle
	UseSLL bool // true when pcap delivers Linux cooked capture (SLL) framing
}

func (l *Listener) Close() { l.Handle.Close() }
