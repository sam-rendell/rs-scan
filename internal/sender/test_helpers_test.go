package sender

import "encoding/binary"

// u32ToIP16 converts a uint32 IPv4 address to [16]byte IPv4-mapped encoding.
// Bytes 10-11 = 0xFF, bytes 12-15 = IPv4 address.
func u32ToIP16(v uint32) [16]byte {
	var ip [16]byte
	ip[10] = 0xFF
	ip[11] = 0xFF
	binary.BigEndian.PutUint32(ip[12:16], v)
	return ip
}
