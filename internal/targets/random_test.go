package targets

import (
	"testing"
)

func TestFeistelPermutation(t *testing.T) {
	size := uint64(100)
	perm := NewFeistelPermutation(size)

	seen := make(map[uint64]bool)
	for i := uint64(0); i < size; i++ {
		val := perm.Permute(i)
		if val >= size {
			t.Errorf("Value %d out of bounds (size %d)", val, size)
		}
		if seen[val] {
			t.Errorf("Duplicate value %d at index %d", val, i)
		}
		seen[val] = true
	}

	if uint64(len(seen)) != size {
		t.Errorf("Expected %d unique values, got %d", size, len(seen))
	}
}

func TestFeistelPermutationLarge(t *testing.T) {
	// Test with a size larger than uint32 can hold — proves 64-bit works.
	// We can't exhaustively check 5B entries, but we can verify no panics
	// and that outputs are in range for a sample.
	size := uint64(5_000_000_000) // 5 billion — exceeds uint32 max
	perm := NewFeistelPermutation(size)

	seen := make(map[uint64]bool)
	for i := uint64(0); i < 10000; i++ {
		val := perm.Permute(i)
		if val >= size {
			t.Fatalf("Value %d out of bounds (size %d) at index %d", val, size, i)
		}
		if seen[val] {
			t.Fatalf("Duplicate value %d at index %d", val, i)
		}
		seen[val] = true
	}
}

func TestRandomCIDRIterator(t *testing.T) {
	// Small range: 192.168.1.0/29 (8 IPs)
	iter, err := NewRandomCIDRIterator("192.168.1.0/29")
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	lastIPU32 := uint32(0)
	isSequential := true

	for {
		ip, ok := iter.Next()
		if !ok {
			break
		}

		ipU32 := IPAddrToUint32(ip)
		if count > 0 {
			if ipU32 != lastIPU32+1 {
				isSequential = false
			}
		}
		lastIPU32 = ipU32
		count++
	}

	if count != 8 {
		t.Errorf("Expected 8 IPs, got %d", count)
	}

	if isSequential {
		t.Logf("Warning: Output was sequential. This might happen by chance with small ranges.")
	}
}
