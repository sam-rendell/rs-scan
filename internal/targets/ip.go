package targets

import (
	"encoding/binary"
	"net"
)

// IPAddr is a fixed-size 16-byte IP address stored in IPv4-mapped IPv6 format.
// IPv4 addresses use the ::ffff:a.b.c.d mapping (bytes 10-11 = 0xFF, bytes 12-15 = IPv4).
// This is stack-allocated and zero-GC, unlike net.IP which is a heap slice.
type IPAddr [16]byte

// v4InV6Prefix is the IPv4-mapped IPv6 prefix: 10 zero bytes + 2 0xFF bytes.
var v4InV6Prefix = [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}

// IPAddrFrom4 creates an IPAddr from 4 IPv4 bytes.
func IPAddrFrom4(a, b, c, d byte) IPAddr {
	var ip IPAddr
	copy(ip[:12], v4InV6Prefix[:])
	ip[12] = a
	ip[13] = b
	ip[14] = c
	ip[15] = d
	return ip
}

// IPAddrFromSlice creates an IPAddr from a byte slice (4 or 16 bytes).
func IPAddrFromSlice(b []byte) IPAddr {
	var ip IPAddr
	switch len(b) {
	case 4:
		copy(ip[:12], v4InV6Prefix[:])
		copy(ip[12:], b)
	case 16:
		copy(ip[:], b)
	}
	return ip
}

// IsIPv4 returns true if this is an IPv4-mapped address.
func (ip IPAddr) IsIPv4() bool {
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0xFF && ip[11] == 0xFF
}

// IsZero returns true if the address is all zeros.
func (ip IPAddr) IsZero() bool {
	return ip == IPAddr{}
}

// V4 returns the last 4 bytes (IPv4 address portion). Only meaningful when IsIPv4().
func (ip IPAddr) V4() [4]byte {
	return [4]byte{ip[12], ip[13], ip[14], ip[15]}
}

// String returns the string representation. IPv4-mapped addresses render as dotted decimal.
func (ip IPAddr) String() string {
	if ip.IsIPv4() {
		return net.IP(ip[12:16]).String()
	}
	return net.IP(ip[:]).String()
}

// ToNetIP converts to net.IP. IPv4-mapped addresses return a 4-byte net.IP.
func (ip IPAddr) ToNetIP() net.IP {
	if ip.IsIPv4() {
		return net.IP{ip[12], ip[13], ip[14], ip[15]}
	}
	out := make(net.IP, 16)
	copy(out, ip[:])
	return out
}

// FromNetIP converts a net.IP to IPAddr. Handles both 4-byte and 16-byte forms.
func FromNetIP(ip net.IP) IPAddr {
	if ip4 := ip.To4(); ip4 != nil {
		return IPAddrFromSlice(ip4)
	}
	if ip16 := ip.To16(); ip16 != nil {
		return IPAddrFromSlice(ip16)
	}
	return IPAddr{}
}

// IPToIPAddr converts a legacy uint32 IPv4 address to IPAddr.
func IPToIPAddr(u uint32) IPAddr {
	var ip IPAddr
	copy(ip[:12], v4InV6Prefix[:])
	binary.BigEndian.PutUint32(ip[12:16], u)
	return ip
}

// IPAddrToUint32 extracts the IPv4 portion as uint32. Returns 0 for IPv6 addresses.
func IPAddrToUint32(ip IPAddr) uint32 {
	if !ip.IsIPv4() {
		return 0
	}
	return binary.BigEndian.Uint32(ip[12:16])
}

// Compare returns -1, 0, or 1 for ordering.
func (ip IPAddr) Compare(other IPAddr) int {
	for i := 0; i < 16; i++ {
		if ip[i] < other[i] {
			return -1
		}
		if ip[i] > other[i] {
			return 1
		}
	}
	return 0
}

// WithPrefix replaces the first 12 bytes (96-bit prefix) of the address.
// Used for NAT64: takes an IPv4-mapped addr and remaps it into a NAT64 prefix.
func (ip IPAddr) WithPrefix(prefix [12]byte) IPAddr {
	var result IPAddr
	copy(result[:12], prefix[:])
	copy(result[12:], ip[12:])
	return result
}

// AddOffset returns a new IPAddr with offset added numerically to the 128-bit address.
// The offset is added to the lower 64 bits with carry into the upper 64 bits.
// Safe for both IPv4-mapped and native IPv6 addresses.
func (ip IPAddr) AddOffset(offset uint64) IPAddr {
	var result IPAddr
	result = ip
	lo := binary.BigEndian.Uint64(result[8:16])
	newLo := lo + offset
	binary.BigEndian.PutUint64(result[8:16], newLo)
	if newLo < lo { // carry
		hi := binary.BigEndian.Uint64(result[0:8])
		binary.BigEndian.PutUint64(result[0:8], hi+1)
	}
	return result
}
