package banner

import "fmt"

// Arena is a pre-allocated pool of fixed-size byte buffers for banner data.
// Zero GC pressure: all returned slices point into a single contiguous backing array.
// Free list is a buffered channel of slot indices.
type Arena struct {
	buf      []byte
	slotSize uint32
	slots    uint32
	free     chan uint32
}

// NewArena creates an arena with the given number of slots and bytes per slot.
// The entire backing buffer is allocated once at startup.
func NewArena(slots, slotSize uint32) *Arena {
	total := uint64(slots) * uint64(slotSize)
	a := &Arena{
		buf:      make([]byte, total),
		slotSize: slotSize,
		slots:    slots,
		free:     make(chan uint32, slots),
	}
	for i := uint32(0); i < slots; i++ {
		a.free <- i
	}
	return a
}

// Alloc returns a slot index and a byte slice backed by the arena.
// Returns ok=false when the arena is full (back-pressure signal).
func (a *Arena) Alloc() (uint32, []byte, bool) {
	select {
	case idx := <-a.free:
		off := uint64(idx) * uint64(a.slotSize)
		slot := a.buf[off : off+uint64(a.slotSize)]
		// No zeroing needed — RecvLen tracks valid data boundaries.
		return idx, slot, true
	default:
		return 0, nil, false
	}
}

// Get returns the byte slice for an existing slot without allocation.
func (a *Arena) Get(idx uint32) []byte {
	if idx >= a.slots {
		return nil
	}
	off := uint64(idx) * uint64(a.slotSize)
	return a.buf[off : off+uint64(a.slotSize)]
}

// Free returns a slot to the pool for reuse.
// Non-blocking: drops the free if the channel is full (indicates double-free bug).
func (a *Arena) Free(idx uint32) {
	if idx >= a.slots {
		return
	}
	select {
	case a.free <- idx:
	default:
		// Channel full — double-free or sentinel bug. Never block the caller.
	}
}

// Available returns the number of free slots.
func (a *Arena) Available() int {
	return len(a.free)
}

// Stats returns arena capacity info.
func (a *Arena) Stats() string {
	return fmt.Sprintf("arena: %d/%d slots free (%dB each)",
		len(a.free), a.slots, a.slotSize)
}
