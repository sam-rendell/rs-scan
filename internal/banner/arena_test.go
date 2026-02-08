package banner

import "testing"

func TestArenaAllocFree(t *testing.T) {
	a := NewArena(4, 64)
	if a.Available() != 4 {
		t.Fatalf("expected 4 free, got %d", a.Available())
	}

	// Alloc all 4 slots
	ids := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		id, buf, ok := a.Alloc()
		if !ok {
			t.Fatalf("alloc %d failed", i)
		}
		if len(buf) != 64 {
			t.Fatalf("slot %d: expected len 64, got %d", i, len(buf))
		}
		ids[i] = id
	}

	if a.Available() != 0 {
		t.Fatalf("expected 0 free, got %d", a.Available())
	}

	// 5th alloc should fail (back-pressure)
	_, _, ok := a.Alloc()
	if ok {
		t.Fatal("expected alloc to fail when arena is full")
	}

	// Free one and re-alloc
	a.Free(ids[1])
	if a.Available() != 1 {
		t.Fatalf("expected 1 free, got %d", a.Available())
	}

	_, buf, ok := a.Alloc()
	if !ok {
		t.Fatal("expected alloc to succeed after free")
	}
	// Should be zeroed
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, b)
		}
	}
}

func TestArenaGet(t *testing.T) {
	a := NewArena(2, 32)
	id, buf, _ := a.Alloc()

	// Write through the alloc slice
	copy(buf, []byte("hello"))

	// Get should return the same backing memory
	got := a.Get(id)
	if string(got[:5]) != "hello" {
		t.Fatalf("Get returned different data: %q", got[:5])
	}
}

func TestArenaGetOutOfBounds(t *testing.T) {
	a := NewArena(2, 32)
	if got := a.Get(999); got != nil {
		t.Fatalf("expected nil for out-of-bounds, got %v", got)
	}
}
