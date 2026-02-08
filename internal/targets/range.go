package targets

import (
	"fmt"
	"strconv"
	"strings"
)

// RangeIterator iterates over custom octet ranges (e.g., "192.168.1-10.1-255").
type RangeIterator struct {
	octets  [4][]int // Pre-calculated values for each octet position
	indices [4]int   // Current index into the octets slices
	started bool     // Helper to handle the first Next() call
}

// NewRangeIterator parses a range string and creates an iterator.
// Format: "A.B.C.D" where each part can be "X" or "X-Y".
func NewRangeIterator(rangeStr string) (*RangeIterator, error) {
	parts := strings.Split(rangeStr, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid IP range format: %s", rangeStr)
	}

	iter := &RangeIterator{}
	for i, part := range parts {
		vals, err := parseOctetRange(part)
		if err != nil {
			return nil, err
		}
		iter.octets[i] = vals
	}

	return iter, nil
}

func parseOctetRange(s string) ([]int, error) {
	if strings.Contains(s, "-") {
		bounds := strings.Split(s, "-")
		if len(bounds) != 2 {
			return nil, fmt.Errorf("invalid range syntax: %s", s)
		}
		start, err1 := strconv.Atoi(bounds[0])
		end, err2 := strconv.Atoi(bounds[1])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("invalid range numbers: %s", s)
		}
		if start < 0 || end > 255 || start > end {
			return nil, fmt.Errorf("invalid octet range: %d-%d", start, end)
		}

		var vals []int
		for v := start; v <= end; v++ {
			vals = append(vals, v)
		}
		return vals, nil
	}

	val, err := strconv.Atoi(s)
	if err != nil {
		return nil, fmt.Errorf("invalid octet: %s", s)
	}
	if val < 0 || val > 255 {
		return nil, fmt.Errorf("octet out of bounds: %d", val)
	}
	return []int{val}, nil
}

func (it *RangeIterator) Next() (uint32, bool) {
	// If the range is empty (shouldn't happen with valid constructor)
	if len(it.octets[0]) == 0 {
		return 0, false
	}

	// Handle first call
	if !it.started {
		it.started = true
		return it.currentIP(), true
	}

	// Increment logic (Working backwards from 4th octet)
	// indices[3]++
	// if indices[3] >= len(octets[3]) { indices[3]=0; indices[2]++ ... }
	
	for i := 3; i >= 0; i-- {
		it.indices[i]++
		if it.indices[i] < len(it.octets[i]) {
			// Successfully incremented this position, no carry needed
			return it.currentIP(), true
		}
		// Reset this position and carry over to the next (left)
		it.indices[i] = 0
	}

	// If we exit the loop, we overflowed the first octet, meaning we are done.
	return 0, false
}

func (it *RangeIterator) currentIP() uint32 {
	ip := (uint32(it.octets[0][it.indices[0]]) << 24) |
		(uint32(it.octets[1][it.indices[1]]) << 16) |
		(uint32(it.octets[2][it.indices[2]]) << 8) |
		(uint32(it.octets[3][it.indices[3]]))
	return ip
}

// Seek for RangeIterator is currently a no-op or naive forward.
// Proper implementation requires reverse-mapping uint32 to the indices.
// For now, to satisfy the interface and since exclusions on complex ranges are rare/small:
func (it *RangeIterator) Seek(target uint32) {
	// Optimization: If target is very far ahead, this is slow.
	// But calculating indices for 1.1-5.1-5 from a flat IP is complex logic.
	// We leave this as a TODO for optimization.
	for {
		// Peek current
		if !it.started {
			// Initialize indices implicitly
			it.started = true
		} else {
			// We need to check if we are behind target
			curr := it.currentIP()
			if curr >= target {
				return
			}
			// Advance
			_, ok := it.Next()
			if !ok {
				return
			}
		}
	}
}

func (it *RangeIterator) GetState() uint64 {
	// Not easily serializable to a single int without custom encoding
	return 0
}

func (it *RangeIterator) SetState(val uint64) {
	// Not supported
}

// Split for RangeIterator is complex due to the disjoint nature.
// For now, we return the iterator itself as a single shard.
// TODO: Implement deep splitting for RangeIterator.
func (it *RangeIterator) Split(n int) []Iterator {
	return []Iterator{it}
}
