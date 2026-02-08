package targets

import (
	"crypto/rand"
	"encoding/binary"
)

const feistelRounds = 6

// FeistelPermutation implements format-preserving encryption on a 64-bit domain.
// Maps indices [0, size) to a random 1-to-1 permutation via cycle-walking.
type FeistelPermutation struct {
	keys      [feistelRounds]uint64
	size      uint64
	halfWidth uint   // bits per half-block
	lowerMask uint64 // (1 << halfWidth) - 1
}

// NewFeistelPermutation creates a permutation for a domain of the given size.
func NewFeistelPermutation(size uint64) *FeistelPermutation {
	// Find smallest even bit-width that covers size
	bits := uint(2)
	for (uint64(1) << bits) < size {
		bits++
	}
	if bits%2 != 0 {
		bits++
	}

	halfWidth := bits / 2
	lowerMask := uint64((1 << halfWidth) - 1)

	var keys [feistelRounds]uint64
	b := make([]byte, feistelRounds*8)
	rand.Read(b)
	for i := 0; i < feistelRounds; i++ {
		keys[i] = binary.LittleEndian.Uint64(b[i*8 : (i+1)*8])
	}

	return &FeistelPermutation{
		keys:      keys,
		size:      size,
		halfWidth: halfWidth,
		lowerMask: lowerMask,
	}
}

// Permute maps input index to a unique output in [0, size).
// Uses cycle-walking: re-encrypt until the result falls within the domain.
func (f *FeistelPermutation) Permute(index uint64) uint64 {
	x := index
	for {
		x = f.encrypt(x)
		if x < f.size {
			return x
		}
	}
}

func (f *FeistelPermutation) encrypt(block uint64) uint64 {
	left := (block >> f.halfWidth) & f.lowerMask
	right := block & f.lowerMask

	for i := 0; i < feistelRounds; i++ {
		roundVal := roundFunc(right, f.keys[i]) & f.lowerMask
		left, right = right, left^roundVal
	}

	return (left << f.halfWidth) | right
}

// roundFunc is a PRF using the murmur3 64-bit finalizer for strong avalanche.
func roundFunc(val, key uint64) uint64 {
	v := val ^ key
	v ^= v >> 33
	v *= 0xff51afd7ed558ccd
	v ^= v >> 33
	v *= 0xc4ceb9fe1a85ec53
	v ^= v >> 33
	return v
}
