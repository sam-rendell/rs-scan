package stack

import "encoding/binary"

// u32ToIPAddr converts a uint32 IPv4 address to IPAddr for tests.
func u32ToIPAddr(v uint32) IPAddr {
	var ip IPAddr
	ip[10] = 0xFF
	ip[11] = 0xFF
	binary.BigEndian.PutUint32(ip[12:16], v)
	return ip
}
