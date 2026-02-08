package targets

import (
	"net"
)

// CIDRIterator iterates over a CIDR block.
type CIDRIterator struct {
	current uint32
	last    uint32
}

// NewCIDRIterator creates a new iterator for the given CIDR string.
func NewCIDRIterator(cidrStr string) (*CIDRIterator, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	start := IPToUint32(ipNet.IP)
	mask := IPToUint32(net.IP(ipNet.Mask))
	// Calculate broadcast address (last IP in range)
	// Invert mask and OR with start
	end := start | (^mask)

	return &CIDRIterator{
		current: start,
		last:    end,
	}, nil
}

// Next returns the next IP in the CIDR range.
func (it *CIDRIterator) Next() (uint32, bool) {
	if it.current > it.last {
		return 0, false
	}
	ip := it.current
	it.current++
	return ip, true
}

// Seek advances the iterator to the target IP.
// If target < current, it does nothing.
func (it *CIDRIterator) Seek(target uint32) {
	if target > it.current {
		it.current = target
	}
}

func (it *CIDRIterator) GetState() uint64 {
	// For CIDR, state is just the current IP
	return uint64(it.current)
}

func (it *CIDRIterator) SetState(val uint64) {
	it.current = uint32(val)
}

// Split divides the CIDR range into n sub-iterators.
func (it *CIDRIterator) Split(n int) []Iterator {
	if n <= 1 {
		return []Iterator{it}
	}

	totalIPs := uint64(it.last) - uint64(it.current) + 1
	if totalIPs < uint64(n) {
		// More shards than IPs, return 1-per-shard until exhausted
		// For simplicity, just return the current one and n-1 empty ones?
		// Better: just return what we have.
		return []Iterator{it}
	}

	perShard := totalIPs / uint64(n)
	var shards []Iterator

	start := it.current
	for i := 0; i < n; i++ {
		end := start + uint32(perShard) - 1
		if i == n-1 {
			end = it.last // Ensure last shard covers everything
		}

		shards = append(shards, &CIDRIterator{
			current: start,
			last:    end,
		})
		start = end + 1
	}

	return shards
}
