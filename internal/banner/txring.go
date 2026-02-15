package banner

import (
	"rs_scan/internal/stack"
	"sync"
	"sync/atomic"
)

// TXRequest represents a response packet to be sent by the Response TX goroutine.
type TXRequest struct {
	DstIP   stack.IPAddr
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Payload []byte // nil for bare ACK/RST, hello bytes for PSH+ACK
}

// TCP flag constants for TXRequest.Flags.
const (
	FlagACK    uint8 = 0x10
	FlagRST    uint8 = 0x04
	FlagPSHACK uint8 = 0x18 // PSH + ACK
	FlagFIN    uint8 = 0x01
	FlagFINACK uint8 = 0x11 // FIN + ACK
)

// TXRing is a MPSC (multi-producer, single-consumer) ring buffer
// for TXRequest structs. Multiple goroutines enqueue (receiver + management);
// the Response TX goroutine dequeues.
type TXRing struct {
	mu   sync.Mutex // protects Enqueue (multiple producers)
	buf  []TXRequest
	mask uint64
	head uint64 // written by producer (Enqueue), read by consumer
	tail uint64 // written by consumer (Dequeue), read by producer
	_pad [56]byte // prevent false sharing between head and tail
}

// NewTXRing creates a ring with capacity rounded up to the next power of two.
// Minimum capacity is 1024.
func NewTXRing(minCap int) *TXRing {
	cap := uint64(1024)
	for cap < uint64(minCap) {
		cap <<= 1
	}
	return &TXRing{
		buf:  make([]TXRequest, cap),
		mask: cap - 1,
	}
}

// Enqueue adds a TXRequest to the ring. Returns false if the ring is full.
// Thread-safe: multiple goroutines may call Enqueue concurrently.
func (r *TXRing) Enqueue(req TXRequest) bool {
	r.mu.Lock()
	head := r.head
	tail := atomic.LoadUint64(&r.tail)
	if head-tail >= uint64(len(r.buf)) {
		r.mu.Unlock()
		return false // full
	}
	r.buf[head&r.mask] = req
	atomic.StoreUint64(&r.head, head+1)
	r.mu.Unlock()
	return true
}

// Dequeue removes and returns the next TXRequest. Returns ok=false if empty.
// Called by the Response TX goroutine (single consumer).
func (r *TXRing) Dequeue() (TXRequest, bool) {
	tail := atomic.LoadUint64(&r.tail)
	head := atomic.LoadUint64(&r.head)
	if tail >= head {
		return TXRequest{}, false // empty
	}
	req := r.buf[tail&r.mask]
	atomic.StoreUint64(&r.tail, tail+1)
	return req, true
}

// DrainBatch dequeues up to max items into dst, returning the count drained.
// This amortizes the atomic loads when the TX goroutine batch-processes.
func (r *TXRing) DrainBatch(dst []TXRequest, max int) int {
	tail := atomic.LoadUint64(&r.tail)
	head := atomic.LoadUint64(&r.head)
	avail := int(head - tail)
	if avail <= 0 {
		return 0
	}
	if avail > max {
		avail = max
	}
	if avail > len(dst) {
		avail = len(dst)
	}
	for i := 0; i < avail; i++ {
		dst[i] = r.buf[(tail+uint64(i))&r.mask]
	}
	atomic.StoreUint64(&r.tail, tail+uint64(avail))
	return avail
}

// Len returns the current number of items in the ring.
func (r *TXRing) Len() int {
	head := atomic.LoadUint64(&r.head)
	tail := atomic.LoadUint64(&r.tail)
	return int(head - tail)
}
