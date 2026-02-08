package targets

import (
	"fmt"
	"net"
	"strings"
)

// Tuple represents a scan target.
type Tuple struct {
	IP   uint32
	Port uint16
}

// TupleIterator iterates over randomized (IP, Port) pairs.
type TupleIterator struct {
	perm      *FeistelPermutation
	ports     []uint16
	ipRanges  []IPRange
	totalIPs  uint64
	totalSize uint64

	// Sharding state
	current   uint64
	end       uint64 // Exclusive

	// Sequential mode: skip Feistel permutation
	sequential bool

	// Filtering
	exclusion *IntervalTree
}

// IPRange helper
type IPRange struct {
	Start           uint32
	Count           uint64
	CumulativeStart uint64
}

// NewTupleIterator creates the master iterator.
// If sequential is true, tuples are emitted in linear order instead of Feistel-permuted.
func NewTupleIterator(targets []string, portSpec string, exclude []string, sequential ...bool) (*TupleIterator, error) {
	seq := len(sequential) > 0 && sequential[0]
	ports, err := ParsePorts(portSpec)
	if err != nil { return nil, err }
	if len(ports) == 0 { return nil, fmt.Errorf("no ports") }

	var ranges []IPRange
	var totalIPs uint64

	for _, t := range targets {
		if strings.Contains(t, "/") {
			iter, err := NewCIDRIterator(t)
			if err != nil { return nil, err }
			count := uint64(iter.last) - uint64(iter.current) + 1
			ranges = append(ranges, IPRange{Start: iter.current, Count: count, CumulativeStart: totalIPs})
			totalIPs += count
		} else {
			ip := IPToUint32(net.ParseIP(t))
			if ip != 0 {
				ranges = append(ranges, IPRange{Start: ip, Count: 1, CumulativeStart: totalIPs})
				totalIPs += 1
			}
		}
	}

	if totalIPs == 0 { return nil, fmt.Errorf("no valid targets") }

	// Exclusion Tree
	var tree *IntervalTree
	if len(exclude) > 0 {
		tree = &IntervalTree{}
		for _, ex := range exclude {
			ex = strings.TrimSpace(ex)
			if ex == "" {
				continue
			}
			if strings.Contains(ex, "/") {
				iter, err := NewCIDRIterator(ex)
				if err != nil {
					return nil, fmt.Errorf("invalid exclusion CIDR %q: %w", ex, err)
				}
				tree.Insert(iter.current, iter.last)
			} else if strings.Contains(ex, "-") {
				parts := strings.SplitN(ex, "-", 2)
				startIP := IPToUint32(net.ParseIP(strings.TrimSpace(parts[0])))
				endIP := IPToUint32(net.ParseIP(strings.TrimSpace(parts[1])))
				if startIP == 0 || endIP == 0 {
					return nil, fmt.Errorf("invalid exclusion range %q", ex)
				}
				tree.Insert(startIP, endIP)
			} else {
				ip := IPToUint32(net.ParseIP(ex))
				if ip == 0 {
					return nil, fmt.Errorf("invalid exclusion IP %q", ex)
				}
				tree.Insert(ip, ip)
			}
		}
	}

	totalSize := totalIPs * uint64(len(ports))

	var perm *FeistelPermutation
	if !seq {
		perm = NewFeistelPermutation(totalSize)
	}

	return &TupleIterator{
		perm:       perm,
		ports:      ports,
		ipRanges:   ranges,
		totalIPs:   totalIPs,
		totalSize:  totalSize,
		current:    0,
		end:        totalSize,
		sequential: seq,
		exclusion:  tree,
	}, nil
}

func (it *TupleIterator) Next() (uint32, uint16, bool) {
	for {
		if it.current >= it.end {
			return 0, 0, false
		}

		var idx uint64
		if it.sequential {
			idx = it.current
		} else {
			idx = it.perm.Permute(it.current)
		}
		it.current++

		numPorts := uint64(len(it.ports))
		portIdx := idx % numPorts
		ipGlobalIdx := idx / numPorts

		ip := it.resolveIP(ipGlobalIdx)
		
		// Check Exclusion
		if it.exclusion != nil {
			if found, _ := it.exclusion.Contains(ip); found {
				continue // Skip and try next index
			}
		}

		port := it.ports[portIdx]
		return ip, port, true
	}
}

func (it *TupleIterator) resolveIP(idx uint64) uint32 {
	for i := len(it.ipRanges) - 1; i >= 0; i-- {
		r := it.ipRanges[i]
		if idx >= r.CumulativeStart {
			return r.Start + uint32(idx - r.CumulativeStart)
		}
	}
	return 0
}

func (it *TupleIterator) GetState() uint64 {
	return it.current
}

func (it *TupleIterator) SetState(val uint64) {
	it.current = val
}

// GetEnd returns the total search space size (exclusive upper bound).
func (it *TupleIterator) GetEnd() uint64 {
	return it.end
}

// TotalIPs returns the number of unique IPs in the iterator.
func (it *TupleIterator) TotalIPs() uint64 {
	return it.totalIPs
}

// TotalPorts returns the number of ports in the iterator.
func (it *TupleIterator) TotalPorts() int {
	return len(it.ports)
}

// Split divides the iterator into N shards.

func (it *TupleIterator) Split(n int) []*TupleIterator {

	var shards []*TupleIterator

	chunkSize := it.totalSize / uint64(n)

	if chunkSize == 0 { chunkSize = 1 }



	start := uint64(0)

	for i := 0; i < n; i++ {

		end := start + chunkSize

		if i == n-1 { end = it.totalSize }

		

		// Clone iterator

		shard := *it

		shard.current = start

		shard.end = end

		

		shards = append(shards, &shard)

		start = end

	}

	return shards

}


