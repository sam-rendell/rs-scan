package targets

import (
	"fmt"
	"net"
	"strings"
)

// Tuple represents a scan target.
type Tuple struct {
	IP   IPAddr
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
	current uint64
	end     uint64 // Exclusive

	// Sequential mode: skip Feistel permutation
	sequential bool

	// Filtering (IPv4 only; IPv6 exclusion deferred)
	exclusion *IntervalTree

	// NAT64: exclusions match against embedded IPv4 (last 4 bytes)
	nat64 bool
}

// IPRange represents a contiguous block of IP addresses.
type IPRange struct {
	BaseIP          IPAddr // First IP in the range
	Count           uint64
	CumulativeStart uint64
}

// NewTupleIterator creates the master iterator.
// Accepts both IPv4 and IPv6 targets (CIDRs, single IPs, IPv4 octet ranges).
// ParseNAT64Prefix parses a NAT64 /96 prefix string into a 12-byte prefix.
// Accepts formats like "2001:67c:2960:6464" or "2001:67c:2960:6464::".
func ParseNAT64Prefix(s string) ([12]byte, error) {
	// Ensure it parses as a valid IPv6 address
	if !strings.Contains(s, "::") {
		s += "::"
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return [12]byte{}, fmt.Errorf("invalid NAT64 prefix %q", s)
	}
	ip = ip.To16()
	if ip == nil {
		return [12]byte{}, fmt.Errorf("invalid NAT64 prefix %q", s)
	}
	var prefix [12]byte
	copy(prefix[:], ip[:12])
	return prefix, nil
}

func NewTupleIterator(targets []string, portSpec string, exclude []string, sequential ...bool) (*TupleIterator, error) {
	seq := len(sequential) > 0 && sequential[0]
	ports, err := ParsePorts(portSpec)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports")
	}

	var ranges []IPRange
	var totalIPs uint64

	for _, t := range targets {
		if strings.Contains(t, "/") {
			base, count, err := parseCIDRRange(t)
			if err != nil {
				return nil, err
			}
			ranges = append(ranges, IPRange{BaseIP: base, Count: count, CumulativeStart: totalIPs})
			totalIPs += count
		} else {
			ip := net.ParseIP(t)
			if ip == nil {
				continue
			}
			addr := FromNetIP(ip)
			if addr.IsZero() {
				continue
			}
			ranges = append(ranges, IPRange{BaseIP: addr, Count: 1, CumulativeStart: totalIPs})
			totalIPs += 1
		}
	}

	if totalIPs == 0 {
		return nil, fmt.Errorf("no valid targets")
	}

	// Exclusion Tree (IPv4 only; IPv6 exclusion support is deferred)
	var tree *IntervalTree
	if len(exclude) > 0 {
		tree = &IntervalTree{}
		for _, ex := range exclude {
			ex = strings.TrimSpace(ex)
			if ex == "" {
				continue
			}
			if strings.Contains(ex, ":") {
				// IPv6 exclusion not yet supported — skip silently
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

// NewNAT64TupleIterator creates a TupleIterator that maps IPv4 targets into a
// NAT64 /96 prefix. IPv4 targets are parsed normally, then their base IPs are
// remapped: prefix[12] + v4[4] → native IPv6 addresses.
func NewNAT64TupleIterator(prefix [12]byte, targets []string, portSpec string, exclude []string, sequential ...bool) (*TupleIterator, error) {
	it, err := NewTupleIterator(targets, portSpec, exclude, sequential...)
	if err != nil {
		return nil, err
	}
	for i := range it.ipRanges {
		if it.ipRanges[i].BaseIP.IsIPv4() {
			it.ipRanges[i].BaseIP = it.ipRanges[i].BaseIP.WithPrefix(prefix)
		}
	}
	it.nat64 = true
	return it, nil
}

func (it *TupleIterator) Next() (IPAddr, uint16, bool) {
	for {
		if it.current >= it.end {
			return IPAddr{}, 0, false
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

		// Check exclusion (IPv4 and NAT64-mapped)
		if it.exclusion != nil {
			var ipU32 uint32
			var check bool
			if ip.IsIPv4() {
				ipU32 = IPAddrToUint32(ip)
				check = true
			} else if it.nat64 {
				ipU32 = uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
				check = true
			}
			if check {
				if found, _ := it.exclusion.Contains(ipU32); found {
					continue
				}
			}
		}

		port := it.ports[portIdx]
		return ip, port, true
	}
}

// resolveIP maps a global IP index to the actual IPAddr using range arithmetic.
func (it *TupleIterator) resolveIP(idx uint64) IPAddr {
	for i := len(it.ipRanges) - 1; i >= 0; i-- {
		r := it.ipRanges[i]
		if idx >= r.CumulativeStart {
			offset := idx - r.CumulativeStart
			return r.BaseIP.AddOffset(offset)
		}
	}
	return IPAddr{}
}

func (it *TupleIterator) GetState() uint64 {
	return it.current
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
	if chunkSize == 0 {
		chunkSize = 1
	}

	start := uint64(0)
	for i := 0; i < n; i++ {
		end := start + chunkSize
		if i == n-1 {
			end = it.totalSize
		}

		shard := *it
		shard.current = start
		shard.end = end

		shards = append(shards, &shard)
		start = end
	}

	return shards
}
