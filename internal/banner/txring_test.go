package banner

import (
	"sync"
	"testing"
)

func TestTXRingBasic(t *testing.T) {
	r := NewTXRing(4)
	// Capacity rounds up to 1024 (minimum)
	if r.Len() != 0 {
		t.Fatalf("expected empty ring, got len %d", r.Len())
	}

	ip1 := u32ToStackIPAddr(1)
	ip2 := u32ToStackIPAddr(2)

	ok := r.Enqueue(TXRequest{DstIP: ip1, Flags: FlagACK})
	if !ok {
		t.Fatal("enqueue failed on empty ring")
	}
	ok = r.Enqueue(TXRequest{DstIP: ip2, Flags: FlagRST})
	if !ok {
		t.Fatal("enqueue failed")
	}

	if r.Len() != 2 {
		t.Fatalf("expected len 2, got %d", r.Len())
	}

	req, ok := r.Dequeue()
	if !ok {
		t.Fatal("dequeue failed")
	}
	if req.DstIP != ip1 || req.Flags != FlagACK {
		t.Fatalf("unexpected request: %+v", req)
	}

	req, ok = r.Dequeue()
	if !ok {
		t.Fatal("dequeue failed")
	}
	if req.DstIP != ip2 {
		t.Fatalf("unexpected DstIP: %v", req.DstIP)
	}

	_, ok = r.Dequeue()
	if ok {
		t.Fatal("expected dequeue to fail on empty ring")
	}
}

func TestTXRingFull(t *testing.T) {
	r := NewTXRing(1024) // will be exactly 1024

	// Fill the ring
	for i := 0; i < 1024; i++ {
		ok := r.Enqueue(TXRequest{DstIP: u32ToStackIPAddr(uint32(i))})
		if !ok {
			t.Fatalf("enqueue failed at %d", i)
		}
	}

	// Should be full
	ip9999 := u32ToStackIPAddr(9999)
	ok := r.Enqueue(TXRequest{DstIP: ip9999})
	if ok {
		t.Fatal("expected enqueue to fail when ring is full")
	}

	// Drain one, then enqueue should work
	r.Dequeue()
	ok = r.Enqueue(TXRequest{DstIP: ip9999})
	if !ok {
		t.Fatal("enqueue should succeed after dequeue")
	}
}

func TestTXRingDrainBatch(t *testing.T) {
	r := NewTXRing(1024)

	for i := 0; i < 10; i++ {
		r.Enqueue(TXRequest{DstIP: u32ToStackIPAddr(uint32(i))})
	}

	dst := make([]TXRequest, 256)
	n := r.DrainBatch(dst, 256)
	if n != 10 {
		t.Fatalf("expected 10 drained, got %d", n)
	}
	for i := 0; i < 10; i++ {
		expectedIP := u32ToStackIPAddr(uint32(i))
		if dst[i].DstIP != expectedIP {
			t.Fatalf("dst[%d].DstIP = %v, want %v", i, dst[i].DstIP, expectedIP)
		}
	}

	if r.Len() != 0 {
		t.Fatalf("expected empty after drain, got %d", r.Len())
	}
}

// TestTXRingMPSC verifies that concurrent Enqueue from multiple goroutines
// doesn't lose entries. Before the MPSC fix, the SPSC Enqueue had a
// load-then-store race that silently dropped ~50% of packets.
func TestTXRingMPSC(t *testing.T) {
	r := NewTXRing(65536)
	const perGoroutine = 5000
	const goroutines = 4

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				for !r.Enqueue(TXRequest{DstIP: u32ToStackIPAddr(uint32(id*perGoroutine + i))}) {
					// Ring full — spin (consumer will drain)
				}
			}
		}(g)
	}

	// Consumer: drain in parallel
	total := 0
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	dst := make([]TXRequest, 256)
	for {
		n := r.DrainBatch(dst, 256)
		total += n
		if n == 0 {
			select {
			case <-done:
				// Drain remainder
				for {
					n = r.DrainBatch(dst, 256)
					if n == 0 {
						break
					}
					total += n
				}
				if total != goroutines*perGoroutine {
					t.Fatalf("lost entries: got %d, want %d", total, goroutines*perGoroutine)
				}
				return
			default:
			}
		}
	}
}
