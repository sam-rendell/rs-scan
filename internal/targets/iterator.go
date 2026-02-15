package targets

import (
	"encoding/binary"
	"net"
)

// Iterator is the interface for generating a sequence of target IPs.
// It is designed to be memory efficient and shardable.
type Iterator interface {
	// Next returns the next IP in the sequence and true.
	// If the sequence is exhausted, it returns zero IPAddr and false.
	Next() (IPAddr, bool)

	// Seek advances the iterator to the specified IP.
	// Used for exclusions.
	Seek(ip IPAddr)

	// GetState returns the current progress index.
	GetState() uint64

	// Split divides the remaining search space into n roughly equal iterators.
	// This is used for parallelizing the scan across multiple sender threads.
	Split(n int) []Iterator
}

// Seeker is a deprecated check in filtered_iterator, merging into main interface.
type Seeker interface {
	Seek(ip IPAddr)
}

// IPToUint32 converts a net.IP to uint32 (compat shim).
func IPToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIP converts a uint32 to net.IP (compat shim).
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
