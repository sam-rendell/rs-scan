package osfp

import "testing"

func TestTTLFamily(t *testing.T) {
	tests := []struct {
		ttl  uint8
		want uint8
	}{
		{1, 32}, {32, 32},
		{33, 64}, {55, 64}, {64, 64},
		{65, 128}, {100, 128}, {128, 128},
		{129, 255}, {200, 255}, {255, 255},
	}
	for _, tc := range tests {
		if got := ttlFamily(tc.ttl); got != tc.want {
			t.Errorf("ttlFamily(%d) = %d, want %d", tc.ttl, got, tc.want)
		}
	}
}

func TestEncodeOptOrder(t *testing.T) {
	// Linux: MSS(2), SACK(4), TS(8), NOP(1), WS(3)
	kinds := []uint8{2, 4, 8, 1, 3}
	o := EncodeOptOrder(kinds)
	want := OptOrder{OptMSS, OptSACK, OptTS, OptNOP, OptWS}
	if o != want {
		t.Errorf("EncodeOptOrder(%v) = %v, want %v", kinds, o, want)
	}
}

func TestEncodeOptOrder_TruncatesOverflow(t *testing.T) {
	kinds := make([]uint8, MaxOpts+5)
	for i := range kinds {
		kinds[i] = 1 // NOP
	}
	o := EncodeOptOrder(kinds)
	for i := 0; i < MaxOpts; i++ {
		if o[i] != OptNOP {
			t.Errorf("slot %d = %d, want %d (NOP)", i, o[i], OptNOP)
		}
	}
}

func TestEncodeOptOrder_UnknownKind(t *testing.T) {
	o := EncodeOptOrder([]uint8{99})
	if o[0] != OptOther {
		t.Errorf("unknown kind 99 → %d, want %d (?)", o[0], OptOther)
	}
}

func TestOptOrderString(t *testing.T) {
	o := EncodeOptOrder([]uint8{2, 4, 8, 1, 3})
	s := o.String()
	if s != "M,S,T,N,W" {
		t.Errorf("String() = %q, want %q", s, "M,S,T,N,W")
	}
}

func TestOptOrderString_Empty(t *testing.T) {
	var o OptOrder
	if s := o.String(); s != "" {
		t.Errorf("empty OptOrder.String() = %q, want %q", s, "")
	}
}

// ── Phase 1 (High) tests ─────────────────────────────────────────────

func TestClassify_LinuxHigh(t *testing.T) {
	fp := TCPFingerprint{
		TTL:        64,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 4, 8, 1, 3}), // M,S,T,N,W
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Linux" || g.Confidence != ConfHigh {
		t.Errorf("Linux SYN-ACK → %+v", g)
	}
}

func TestClassify_LinuxDecayedTTL(t *testing.T) {
	// TTL=34 → ttlFamily=64, still matches Linux high
	fp := TCPFingerprint{
		TTL:        34,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 4, 8, 1, 3}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Linux" || g.Confidence != ConfHigh {
		t.Errorf("Linux TTL=34 → %+v, want Linux/high", g)
	}
}

func TestClassify_LinuxAlternate(t *testing.T) {
	// M,N,N,S,N,W — 6% of Linux
	fp := TCPFingerprint{
		TTL:      64,
		DF:       true,
		OptOrder: EncodeOptOrder([]uint8{2, 1, 1, 4, 1, 3}),
	}
	g := Classify(&fp)
	if g.Family != "Linux" || g.Confidence != ConfHigh {
		t.Errorf("Linux alternate → %+v", g)
	}
}

func TestClassify_WindowsNewHigh(t *testing.T) {
	// M,N,W,N,N,T,N,N,S — dominant Windows 10+ sig
	fp := TCPFingerprint{
		TTL:        128,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 1, 3, 1, 1, 8, 1, 1, 4}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Windows" || g.Confidence != ConfHigh {
		t.Errorf("Windows new → %+v", g)
	}
}

func TestClassify_WindowsBSD_TTL128(t *testing.T) {
	// M,N,W,S,T + TTL=128 + DF → Windows (shared sig)
	fp := TCPFingerprint{
		TTL:        128,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 1, 3, 4, 8}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Windows" || g.Confidence != ConfHigh {
		t.Errorf("Windows M,N,W,S,T TTL=128 → %+v", g)
	}
}

func TestClassify_WindowsLegacyHigh(t *testing.T) {
	// M,N,W,N,N,S + TTL=128 — XP/2003
	fp := TCPFingerprint{
		TTL:      128,
		OptOrder: EncodeOptOrder([]uint8{2, 1, 3, 1, 1, 4}),
	}
	g := Classify(&fp)
	if g.Family != "Windows" || g.Confidence != ConfHigh {
		t.Errorf("Windows legacy → %+v", g)
	}
}

func TestClassify_FreeBSDHigh(t *testing.T) {
	// M,N,W,S,T + TTL=64 + DF → FreeBSD (shared sig)
	fp := TCPFingerprint{
		TTL:        64,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 1, 3, 4, 8}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "FreeBSD" || g.Confidence != ConfHigh {
		t.Errorf("FreeBSD → %+v", g)
	}
}

func TestClassify_MacOSHigh(t *testing.T) {
	// M,N,W,N,N,T,S,E,E + TTL=64 + DF
	fp := TCPFingerprint{
		TTL:        64,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 1, 3, 1, 1, 8, 4, 0, 0}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "macOS" || g.Confidence != ConfHigh {
		t.Errorf("macOS → %+v", g)
	}
}

func TestClassify_SolarisHigh(t *testing.T) {
	// N,N,T,M,N,W,N,N,S + TTL=64 + DF
	fp := TCPFingerprint{
		TTL:        64,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{1, 1, 8, 2, 1, 3, 1, 1, 4}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Solaris" || g.Confidence != ConfHigh {
		t.Errorf("Solaris → %+v", g)
	}
}

func TestClassify_SolarisAlt(t *testing.T) {
	// S,T,M,N,W + TTL=64 + DF → Solaris (medium — only 40% purity)
	fp := TCPFingerprint{
		TTL:        64,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{4, 8, 2, 1, 3}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Solaris" || g.Confidence != ConfMedium {
		t.Errorf("Solaris alt → %+v, want Solaris/medium", g)
	}
}

func TestClassify_OpenBSDHigh(t *testing.T) {
	// M,N,N,S,N,W,N,N,T + TTL=64
	fp := TCPFingerprint{
		TTL:        64,
		OptOrder:   EncodeOptOrder([]uint8{2, 1, 1, 4, 1, 3, 1, 1, 8}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "OpenBSD" || g.Confidence != ConfHigh {
		t.Errorf("OpenBSD → %+v", g)
	}
}

func TestClassify_NetDeviceMSSOnly(t *testing.T) {
	fp := TCPFingerprint{
		TTL:      255,
		OptOrder: EncodeOptOrder([]uint8{2}),
	}
	g := Classify(&fp)
	if g.Family != "NetDevice" || g.Confidence != ConfHigh {
		t.Errorf("NetDevice MSS-only → %+v", g)
	}
}

func TestClassify_NetDeviceNoOptions(t *testing.T) {
	fp := TCPFingerprint{TTL: 255}
	g := Classify(&fp)
	if g.Family != "NetDevice" || g.Confidence != ConfHigh {
		t.Errorf("NetDevice no opts → %+v", g)
	}
}

// ── Phase 2 (Medium) tests ───────────────────────────────────────────

func TestClassify_WindowsNewMismatchedTTL(t *testing.T) {
	// Windows new sig but TTL=60 → medium
	fp := TCPFingerprint{
		TTL:        60,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 1, 3, 1, 1, 8, 1, 1, 4}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Windows" || g.Confidence != ConfMedium {
		t.Errorf("Windows new TTL=60 → %+v, want medium", g)
	}
}

func TestClassify_LinuxMismatchedTTL(t *testing.T) {
	// Linux options but TTL=200 → medium
	fp := TCPFingerprint{
		TTL:        200,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 4, 8, 1, 3}),
		Timestamps: true,
	}
	g := Classify(&fp)
	if g.Family != "Linux" || g.Confidence != ConfMedium {
		t.Errorf("Linux TTL=200 → %+v, want medium", g)
	}
}

func TestClassify_NetDeviceMSSOnlyNon255(t *testing.T) {
	// MSS-only but TTL=64 → medium
	fp := TCPFingerprint{
		TTL:      64,
		OptOrder: EncodeOptOrder([]uint8{2}),
	}
	g := Classify(&fp)
	if g.Family != "NetDevice" || g.Confidence != ConfMedium {
		t.Errorf("NetDevice MSS-only TTL=64 → %+v, want medium", g)
	}
}

// ── Phase 3 (Low) tests ──────────────────────────────────────────────

func TestClassify_UnknownOptsFallback(t *testing.T) {
	// TTL=55 (→64), unknown options
	fp := TCPFingerprint{
		TTL:      55,
		OptOrder: EncodeOptOrder([]uint8{2, 3}), // non-standard
	}
	g := Classify(&fp)
	if g.Family != "Linux" || g.Confidence != ConfLow {
		t.Errorf("TTL=55 unknown opts → %+v, want Linux/low", g)
	}
}

func TestClassify_TTL128FallbackWindows(t *testing.T) {
	fp := TCPFingerprint{
		TTL:      120,
		OptOrder: EncodeOptOrder([]uint8{2, 3, 4}), // non-standard
	}
	g := Classify(&fp)
	if g.Family != "Windows" || g.Confidence != ConfLow {
		t.Errorf("TTL=120 unknown opts → %+v, want Windows/low", g)
	}
}

// ── Shared sig disambiguation ────────────────────────────────────────

func TestClassify_WinBSD_AmbiguousTTL(t *testing.T) {
	// M,N,W,S,T at TTL=200 (→255) — neither 64 nor 128, DF=Y → low/Windows
	fp := TCPFingerprint{
		TTL:      200,
		DF:       true,
		OptOrder: EncodeOptOrder([]uint8{2, 1, 3, 4, 8}),
	}
	g := Classify(&fp)
	if g.Family != "Windows" || g.Confidence != ConfLow {
		t.Errorf("WinBSD TTL=200 → %+v, want Windows/low", g)
	}
}

// ── Scan output regression: BigIP F5 ─────────────────────────────────

func TestClassify_BigIP_MSSOnly_TTL255(t *testing.T) {
	// Real scan: BigIP F5 — TTL=243(→255), Window=22080, MSS=1380, opts=M only
	fp := TCPFingerprint{
		TTL:      243,
		DF:       true,
		Window:   22080,
		MSS:      1380,
		WScale:   0xFF,
		OptOrder: EncodeOptOrder([]uint8{2}),
	}
	g := Classify(&fp)
	if g.Family != "NetDevice" || g.Confidence != ConfHigh {
		t.Errorf("BigIP F5 TTL=243 → %+v, want NetDevice/high", g)
	}
}

func TestClassify_GoogleDNS_MSSOnly_TTL128(t *testing.T) {
	// Real scan: Google 8.8.8.53 — TTL=124(→128), Window=65535, MSS=1412, opts=M only
	fp := TCPFingerprint{
		TTL:      124,
		DF:       true,
		Window:   65535,
		MSS:      1412,
		WScale:   0xFF,
		OptOrder: EncodeOptOrder([]uint8{2}),
	}
	g := Classify(&fp)
	if g.Family != "NetDevice" || g.Confidence != ConfMedium {
		t.Errorf("Google DNS TTL=124 → %+v, want NetDevice/medium", g)
	}
}

// ── Confidence string ────────────────────────────────────────────────

func TestConfidenceString(t *testing.T) {
	tests := []struct {
		c    Confidence
		want string
	}{
		{ConfHigh, "high"},
		{ConfMedium, "medium"},
		{ConfLow, "low"},
		{ConfNone, ""},
	}
	for _, tc := range tests {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("Confidence(%d).String() = %q, want %q", tc.c, got, tc.want)
		}
	}
}

// ── Benchmarks ───────────────────────────────────────────────────────

func BenchmarkClassify(b *testing.B) {
	fp := TCPFingerprint{
		TTL:        64,
		DF:         true,
		OptOrder:   EncodeOptOrder([]uint8{2, 4, 8, 1, 3}),
		Timestamps: true,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Classify(&fp)
	}
}

func BenchmarkClassify_Fallback(b *testing.B) {
	fp := TCPFingerprint{
		TTL:      55,
		OptOrder: EncodeOptOrder([]uint8{99, 98, 97}),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Classify(&fp)
	}
}

func BenchmarkEncodeOptOrder(b *testing.B) {
	kinds := []uint8{2, 4, 8, 1, 3}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		EncodeOptOrder(kinds)
	}
}
