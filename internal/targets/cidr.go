package targets

import (
	"fmt"
	"math"
	"net"
)

// CIDRIterator iterates over a CIDR block (IPv4 only, used by RandomCIDRIterator).
type CIDRIterator struct {
	current uint32
	last    uint32
}

// NewCIDRIterator creates a new iterator for the given IPv4 CIDR string.
func NewCIDRIterator(cidrStr string) (*CIDRIterator, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	if ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("CIDRIterator only supports IPv4; use parseCIDRRange for IPv6")
	}

	start := IPToUint32(ipNet.IP)
	mask := IPToUint32(net.IP(ipNet.Mask))
	end := start | (^mask)

	return &CIDRIterator{
		current: start,
		last:    end,
	}, nil
}

// Next returns the next IP in the CIDR range.
func (it *CIDRIterator) Next() (IPAddr, bool) {
	if it.current > it.last {
		return IPAddr{}, false
	}
	ip := it.current
	it.current++
	return IPToIPAddr(ip), true
}

// Seek advances the iterator to the target IP.
func (it *CIDRIterator) Seek(target IPAddr) {
	t := IPAddrToUint32(target)
	if t > it.current {
		it.current = t
	}
}

func (it *CIDRIterator) GetState() uint64 {
	return uint64(it.current)
}

// Split divides the CIDR range into n sub-iterators.
func (it *CIDRIterator) Split(n int) []Iterator {
	if n <= 1 {
		return []Iterator{it}
	}

	totalIPs := uint64(it.last) - uint64(it.current) + 1
	if totalIPs < uint64(n) {
		return []Iterator{it}
	}

	perShard := totalIPs / uint64(n)
	var shards []Iterator

	start := it.current
	for i := 0; i < n; i++ {
		end := start + uint32(perShard) - 1
		if i == n-1 {
			end = it.last
		}

		shards = append(shards, &CIDRIterator{
			current: start,
			last:    end,
		})
		start = end + 1
	}

	return shards
}

// parseCIDRRange parses a CIDR string and returns the base IP and host count.
// Supports both IPv4 and IPv6 CIDRs.
// IPv6 prefixes shorter than /64 are rejected as too large for practical scanning.
func parseCIDRRange(cidrStr string) (IPAddr, uint64, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return IPAddr{}, 0, err
	}

	ones, bits := ipNet.Mask.Size()

	if bits == 32 {
		// IPv4
		start := IPToUint32(ipNet.IP)
		mask := IPToUint32(net.IP(ipNet.Mask))
		end := start | (^mask)
		count := uint64(end) - uint64(start) + 1
		return FromNetIP(ipNet.IP), count, nil
	}

	// IPv6 (bits == 128)
	hostBits := 128 - ones
	if hostBits > 64 {
		return IPAddr{}, 0, fmt.Errorf("IPv6 prefix /%d too large for scanning (minimum /64)", ones)
	}

	var count uint64
	if hostBits == 64 {
		count = math.MaxUint64 // 2^64 - 1 (close enough for practical purposes)
	} else {
		count = uint64(1) << hostBits
	}

	return FromNetIP(ipNet.IP), count, nil
}
