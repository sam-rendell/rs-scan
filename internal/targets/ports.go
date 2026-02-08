package targets

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePorts expands a string like "80,443,1000-1005" into a slice of uint16.
func ParsePorts(spec string) ([]uint16, error) {
	var ports []uint16
	parts := strings.Split(spec, ",")

	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port numbers: %s", part)
			}
			if start > end || start < 0 || end > 65535 {
				return nil, fmt.Errorf("invalid port range bounds: %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				ports = append(ports, uint16(p))
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p < 0 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			ports = append(ports, uint16(p))
		}
	}
	return ports, nil
}

// ParsePortSpec parses nmap-style port specifications with protocol prefixes.
// Supports: "T:80,443", "U:53,161", "T:22,80,U:53,161", "80,443" (bare ports).
// Bare ports (no prefix) are assigned to the protocol indicated by defaultProto
// ("tcp", "udp", or "both").
func ParsePortSpec(spec string, defaultProto string) (tcp []uint16, udp []uint16, err error) {
	// Split on comma but respect T: and U: prefixes.
	// Strategy: split into segments delimited by T: or U: prefixes.
	// "T:22,80,U:53,161,8080" → segments: [{proto:"tcp", spec:"22,80"}, {proto:"udp", spec:"53,161,8080"}]
	type segment struct {
		proto string
		spec  string
	}

	var segments []segment
	remaining := spec

	for remaining != "" {
		// Find next prefix
		var proto string
		if strings.HasPrefix(remaining, "T:") || strings.HasPrefix(remaining, "t:") {
			proto = "tcp"
			remaining = remaining[2:]
		} else if strings.HasPrefix(remaining, "U:") || strings.HasPrefix(remaining, "u:") {
			proto = "udp"
			remaining = remaining[2:]
		} else {
			proto = "" // bare — uses defaultProto
		}

		// Find where the next prefix starts (look for ,T: or ,U:)
		end := len(remaining)
		for i := 0; i < len(remaining)-1; i++ {
			if remaining[i] == ',' {
				next := remaining[i+1:]
				if strings.HasPrefix(next, "T:") || strings.HasPrefix(next, "t:") ||
					strings.HasPrefix(next, "U:") || strings.HasPrefix(next, "u:") {
					end = i
					break
				}
			}
		}

		segSpec := remaining[:end]
		if end < len(remaining) {
			remaining = remaining[end+1:] // skip the comma
		} else {
			remaining = ""
		}

		if segSpec != "" {
			segments = append(segments, segment{proto: proto, spec: segSpec})
		}
	}

	for _, seg := range segments {
		ports, perr := ParsePorts(seg.spec)
		if perr != nil {
			return nil, nil, perr
		}

		proto := seg.proto
		if proto == "" {
			proto = defaultProto
		}

		switch proto {
		case "tcp":
			tcp = append(tcp, ports...)
		case "udp":
			udp = append(udp, ports...)
		case "both":
			tcp = append(tcp, ports...)
			udp = append(udp, ports...)
		default:
			return nil, nil, fmt.Errorf("unknown protocol: %s", proto)
		}
	}

	return tcp, udp, nil
}
