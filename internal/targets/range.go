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

func (it *RangeIterator) Next() (IPAddr, bool) {
	// If the range is empty (shouldn't happen with valid constructor)
	if len(it.octets[0]) == 0 {
		return IPAddr{}, false
	}

	// Handle first call
	if !it.started {
		it.started = true
		return it.currentIP(), true
	}

	// Increment logic (Working backwards from 4th octet)
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
	return IPAddr{}, false
}

func (it *RangeIterator) currentIP() IPAddr {
	return IPAddrFrom4(
		byte(it.octets[0][it.indices[0]]),
		byte(it.octets[1][it.indices[1]]),
		byte(it.octets[2][it.indices[2]]),
		byte(it.octets[3][it.indices[3]]),
	)
}

// Seek for RangeIterator is currently a no-op or naive forward.
func (it *RangeIterator) Seek(target IPAddr) {
	tU32 := IPAddrToUint32(target)
	for {
		if !it.started {
			it.started = true
		} else {
			curr := IPAddrToUint32(it.currentIP())
			if curr >= tU32 {
				return
			}
			_, ok := it.Next()
			if !ok {
				return
			}
		}
	}
}

func (it *RangeIterator) GetState() uint64 {
	return 0
}

// Split for RangeIterator is complex due to the disjoint nature.
// For now, we return the iterator itself as a single shard.
func (it *RangeIterator) Split(n int) []Iterator {
	return []Iterator{it}
}
