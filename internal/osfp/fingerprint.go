package osfp

import "strings"

// TCPFingerprint holds raw TCP/IP signals from a SYN-ACK packet.
// All value types — zero allocation to capture.
type TCPFingerprint struct {
	TTL        uint8
	DF         bool     // IPv4 Don't Fragment
	Window     uint16   // TCP advertised window
	MSS        uint16   // MSS option value (0 if absent)
	WScale     uint8    // Window Scale value (0xFF if absent)
	SACKPerm   bool     // SACK Permitted present
	Timestamps bool     // TCP Timestamps present
	ECE        bool
	CWR        bool
	OptOrder   OptOrder // encoded TCP option ordering
}

// OptKind represents a TCP option kind for fingerprint ordering.
type OptKind uint8

const (
	OptEnd   OptKind = 0
	OptNOP   OptKind = 'N'
	OptMSS   OptKind = 'M'
	OptWS    OptKind = 'W'
	OptSACK  OptKind = 'S'
	OptTS    OptKind = 'T'
	OptEOL   OptKind = 'E'
	OptOther OptKind = '?'
)

// MaxOpts is the maximum number of TCP options tracked in a fingerprint.
const MaxOpts = 12

// OptOrder is a fixed-size encoding of TCP option kinds, enabling
// zero-alloc == comparison (compiles to memcmp).
type OptOrder [MaxOpts]OptKind

// EncodeOptOrder builds an OptOrder from raw TCP option kind byte values.
func EncodeOptOrder(kinds []uint8) OptOrder {
	var o OptOrder
	n := len(kinds)
	if n > MaxOpts {
		n = MaxOpts
	}
	for i := 0; i < n; i++ {
		switch kinds[i] {
		case 0:
			o[i] = OptEOL
		case 1:
			o[i] = OptNOP
		case 2:
			o[i] = OptMSS
		case 3:
			o[i] = OptWS
		case 4:
			o[i] = OptSACK
		case 8:
			o[i] = OptTS
		default:
			o[i] = OptOther
		}
	}
	return o
}

// String returns a comma-separated representation like "M,S,T,N,W".
func (o OptOrder) String() string {
	var parts []string
	for _, k := range o {
		if k == OptEnd {
			break
		}
		parts = append(parts, string(rune(k)))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ",")
}

// Confidence level for OS guess.
type Confidence uint8

const (
	ConfNone   Confidence = 0
	ConfLow    Confidence = 1
	ConfMedium Confidence = 2
	ConfHigh   Confidence = 3
)

// String returns the confidence as a lowercase string.
func (c Confidence) String() string {
	switch c {
	case ConfHigh:
		return "high"
	case ConfMedium:
		return "medium"
	case ConfLow:
		return "low"
	default:
		return ""
	}
}

// OSGuess is the classifier output.
type OSGuess struct {
	Family     string     // "Linux", "Windows", "macOS", "FreeBSD", "Solaris", "NetDevice", "Unknown"
	Confidence Confidence // high/medium/low/none
}
