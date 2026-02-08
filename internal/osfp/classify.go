package osfp

// Pre-computed option order signatures for common OS families.
// Derived from analysis of 5,484 nmap-os-db fingerprints.
//
// Signature coverage by OS family:
//   Linux:    M,S,T,N,W (68.3%)
//   Windows:  M,N,W,N,N,T,N,N,S (44.7%) + M,N,W,S,T@128 (26.2%) + M,N,W,N,N,S (10.5%)
//   macOS:    M,N,W,N,N,T,S,L,L (70.7%)
//   FreeBSD:  M,N,W,S,T@64 (58.0%) + M,N,W,N,N,T,S,L,L (15.9%)
//   Solaris:  N,N,T,M,N,W,N,N,S (47.1%) + S,T,M,N,W (20.0%)
//   OpenBSD:  M,N,N,S,N,W,N,N,T (97.6%)

var (
	// Linux 2.6+: MSS, SACK_PERM, Timestamps, NOP, WScale — 68% of Linux
	sigLinux = EncodeOptOrder([]uint8{2, 4, 8, 1, 3})

	// Windows 10/11/Server 2016+: MSS, NOP, WScale, NOP, NOP, TS, NOP, NOP, SACK — 45% of Windows
	sigWinNew = EncodeOptOrder([]uint8{2, 1, 3, 1, 1, 8, 1, 1, 4})

	// Windows Vista/7/8/Server 2008-2012: MSS, NOP, WScale, SACK, TS — 26% of Windows
	// NOTE: Same sig as FreeBSD at TTL=64 — TTL discriminates
	sigWinBSD = EncodeOptOrder([]uint8{2, 1, 3, 4, 8})

	// Windows XP/2003 (legacy, no timestamps): MSS, NOP, WScale, NOP, NOP, SACK — 10.5% of Windows
	sigWinLegacy = EncodeOptOrder([]uint8{2, 1, 3, 1, 1, 4})

	// macOS/iOS/XNU: MSS, NOP, WScale, NOP, NOP, TS, SACK, EOL, EOL — 71% of macOS
	// Also covers ~16% of FreeBSD and 88% of iOS
	sigXNU = EncodeOptOrder([]uint8{2, 1, 3, 1, 1, 8, 4, 0, 0})

	// FreeBSD (also ESXi): MSS, NOP, WScale, SACK, TS — 58% of FreeBSD
	// Same bytes as sigWinBSD; TTL at 64 → FreeBSD, at 128 → Windows
	sigFreeBSD = sigWinBSD

	// Solaris (primary): NOP, NOP, TS, MSS, NOP, WScale, NOP, NOP, SACK — 47% of Solaris
	sigSolaris = EncodeOptOrder([]uint8{1, 1, 8, 2, 1, 3, 1, 1, 4})

	// Solaris (alternate): SACK, TS, MSS, NOP, WScale — 20% of Solaris
	sigSolaris2 = EncodeOptOrder([]uint8{4, 8, 2, 1, 3})

	// OpenBSD: MSS, NOP, NOP, SACK, NOP, WScale, NOP, NOP, TS — 97.6% of OpenBSD
	sigOpenBSD = EncodeOptOrder([]uint8{2, 1, 1, 4, 1, 3, 1, 1, 8})

	// Linux alternate: MSS, NOP, NOP, SACK, NOP, WScale — 6% of Linux
	sigLinux2 = EncodeOptOrder([]uint8{2, 1, 1, 4, 1, 3})

	// Network devices (minimal): MSS only
	sigMinimalMSS = EncodeOptOrder([]uint8{2})
)

// ttlFamily normalizes a wire TTL to its likely initial TTL value.
func ttlFamily(ttl uint8) uint8 {
	switch {
	case ttl <= 32:
		return 32
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default:
		return 255
	}
}

// Classify performs best-effort OS identification from TCP/IP SYN-ACK signals.
// Signatures and confidence weights are derived from nmap-os-db analysis.
//
// Three-phase cascade:
//   Phase 1 (High):   TTL family + exact option order + secondary signals
//   Phase 2 (Medium): Option order matches but TTL is unexpected (many hops / tunneled)
//   Phase 3 (Low):    TTL family only (no useful options)
//
// Pure function, zero allocations.
func Classify(fp *TCPFingerprint) OSGuess {
	ttl := ttlFamily(fp.TTL)
	opts := fp.OptOrder

	// Phase 1: High confidence — TTL family + option order + signals
	switch {
	// Linux: M,S,T,N,W + TTL=64 + TS — 66% purity (embedded bleeds in, but dominant)
	case opts == sigLinux && ttl == 64 && fp.Timestamps && fp.DF:
		return OSGuess{Family: "Linux", Confidence: ConfHigh}

	// Linux alternate: M,N,N,S,N,W + TTL=64 + DF — 68% purity
	case opts == sigLinux2 && ttl == 64 && fp.DF:
		return OSGuess{Family: "Linux", Confidence: ConfHigh}

	// Windows new: M,N,W,N,N,T,N,N,S + TTL=128 — 93% purity
	case opts == sigWinNew && ttl == 128:
		return OSGuess{Family: "Windows", Confidence: ConfHigh}

	// Windows/FreeBSD shared sig: M,N,W,S,T — TTL discriminates
	// TTL=128 + DF → Windows (99% purity)
	case opts == sigWinBSD && ttl == 128 && fp.DF:
		return OSGuess{Family: "Windows", Confidence: ConfHigh}
	// TTL=64 + DF → FreeBSD/ESXi (63% purity)
	case opts == sigFreeBSD && ttl == 64 && fp.DF:
		return OSGuess{Family: "FreeBSD", Confidence: ConfHigh}

	// Windows legacy: M,N,W,N,N,S + TTL=128 — 100% purity
	case opts == sigWinLegacy && ttl == 128:
		return OSGuess{Family: "Windows", Confidence: ConfHigh}

	// macOS/iOS/XNU: M,N,W,N,N,T,S,E,E + TTL=64 + DF + TS — mixed but dominant Apple
	case opts == sigXNU && ttl == 64 && fp.DF && fp.Timestamps:
		return OSGuess{Family: "macOS", Confidence: ConfHigh}

	// Solaris: N,N,T,M,N,W,N,N,S + TTL=64 + DF — 72% purity
	case opts == sigSolaris && ttl == 64 && fp.DF:
		return OSGuess{Family: "Solaris", Confidence: ConfHigh}

	// Solaris alternate: S,T,M,N,W + TTL=64 + DF — 40% Solaris, 31% Linux
	case opts == sigSolaris2 && ttl == 64 && fp.DF:
		return OSGuess{Family: "Solaris", Confidence: ConfMedium}

	// OpenBSD: M,N,N,S,N,W,N,N,T + TTL=64 — 97.6% purity
	case opts == sigOpenBSD && ttl == 64:
		return OSGuess{Family: "OpenBSD", Confidence: ConfHigh}

	// Network device: TTL=255 + MSS-only or no options — characteristic of embedded
	case ttl == 255 && (opts == sigMinimalMSS || opts == OptOrder{}):
		return OSGuess{Family: "NetDevice", Confidence: ConfHigh}
	}

	// Phase 2: Medium confidence — option order matches but unexpected TTL
	switch {
	case opts == sigLinux && fp.Timestamps:
		return OSGuess{Family: "Linux", Confidence: ConfMedium}
	case opts == sigLinux2:
		return OSGuess{Family: "Linux", Confidence: ConfMedium}
	case opts == sigWinNew:
		return OSGuess{Family: "Windows", Confidence: ConfMedium}
	case opts == sigWinLegacy:
		return OSGuess{Family: "Windows", Confidence: ConfMedium}
	case opts == sigXNU && fp.Timestamps:
		return OSGuess{Family: "macOS", Confidence: ConfMedium}
	case opts == sigSolaris:
		return OSGuess{Family: "Solaris", Confidence: ConfMedium}
	case opts == sigOpenBSD:
		return OSGuess{Family: "OpenBSD", Confidence: ConfMedium}
	// WinBSD ambiguous without TTL — report as generic
	case opts == sigWinBSD && fp.DF:
		return OSGuess{Family: "Windows", Confidence: ConfLow}
	case opts == sigMinimalMSS:
		return OSGuess{Family: "NetDevice", Confidence: ConfMedium}
	case opts == OptOrder{}:
		return OSGuess{Family: "NetDevice", Confidence: ConfMedium}
	}

	// Phase 3: Low confidence — TTL family heuristic only
	switch ttl {
	case 128:
		return OSGuess{Family: "Windows", Confidence: ConfLow}
	case 255:
		return OSGuess{Family: "NetDevice", Confidence: ConfLow}
	case 64:
		return OSGuess{Family: "Linux", Confidence: ConfLow}
	case 32:
		return OSGuess{Family: "Unknown", Confidence: ConfLow}
	}

	return OSGuess{Family: "Unknown", Confidence: ConfNone}
}
