package banner

import "rs_scan/internal/stack"

// u32ToStackIPAddr converts a uint32 IPv4 address (big-endian) to stack.IPAddr.
// Uses IPv4-mapped IPv6 encoding: bytes 10-11 = 0xFF, bytes 12-15 = IPv4.
func u32ToStackIPAddr(v uint32) stack.IPAddr {
	var ip stack.IPAddr
	ip[10] = 0xFF
	ip[11] = 0xFF
	ip[12] = byte(v >> 24)
	ip[13] = byte(v >> 16)
	ip[14] = byte(v >> 8)
	ip[15] = byte(v)
	return ip
}
