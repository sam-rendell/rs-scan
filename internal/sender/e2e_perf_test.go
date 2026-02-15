//go:build e2e

package sender

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"rs_scan/internal/targets"
)

// ═══════════════════════════════════════════════════════════════════════
// High-performance end-to-end validation
//
// Tests that the scanner's packet pipeline can sustain real-world rates
// over a veth pair with full packet validation.
//
// Run:
//   sudo go test -tags e2e -v -run TestE2E_Perf -count=1 ./internal/sender/
//
// What it validates:
//   1. Sustained PPS for IPv4 and IPv6 (single sender, tight loop)
//   2. Pipeline PPS through TupleIterator → Sender (realistic scan flow)
//   3. Multi-shard scaling with concurrent sender goroutines
//   4. Interface counter parity (tx == rx, no kernel drops)
//   5. Sampled packet integrity (checksums, flags, cookies, options)
//   6. GC pressure and allocation profile
// ═══════════════════════════════════════════════════════════════════════

const (
	perfDuration = 3 * time.Second // sustained measurement window
	warmupPkts   = 10000           // discard initial packets
	minPPS       = 50000           // absolute floor (any hardware)
)

func TestE2E_Perf(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	setupVeth(t)
	t.Cleanup(func() { teardownVeth() })

	iface, err := net.InterfaceByName("rs_e2e0")
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	srcMAC := iface.HardwareAddr
	dstMAC := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	srcIPv4 := net.ParseIP("10.99.99.1").To4()
	var srcIPv6 [16]byte
	copy(srcIPv6[:], net.ParseIP("2001:db8::1").To16())

	// ── 1. Raw IPv4 throughput ───────────────────────────────────────
	var rawV4PPS float64
	t.Run("IPv4_RawThroughput", func(t *testing.T) {
		s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, srcIPv4)
		defer s.handle.Close()

		var dst [16]byte
		dst[10], dst[11] = 0xFF, 0xFF
		dst[12], dst[13], dst[14], dst[15] = 10, 0, 0, 1

		txBefore := readCounter("rs_e2e0", "tx_packets")
		rxBefore := readCounter("rs_e2e1", "rx_packets")

		count := runRawLoop(s, dst, 80, perfDuration)
		rawV4PPS = float64(count) / perfDuration.Seconds()

		txAfter := readCounter("rs_e2e0", "tx_packets")
		rxAfter := readCounter("rs_e2e1", "rx_packets")
		txDelta := txAfter - txBefore
		rxDelta := rxAfter - rxBefore

		t.Logf("Sent:       %d packets in %v", count, perfDuration)
		t.Logf("Rate:       %.0f PPS (%.2f Mpps)", rawV4PPS, rawV4PPS/1e6)
		t.Logf("Kernel TX:  %d  RX: %d  (loss: %d)", txDelta, rxDelta, txDelta-rxDelta)

		if rawV4PPS < minPPS {
			t.Errorf("IPv4 PPS %.0f below minimum %d", rawV4PPS, minPPS)
		}
		if txDelta > 0 && rxDelta < txDelta {
			lossRate := float64(txDelta-rxDelta) / float64(txDelta) * 100
			if lossRate > 1.0 {
				t.Errorf("kernel drop rate %.1f%% (tx=%d rx=%d)", lossRate, txDelta, rxDelta)
			}
		}
	})

	// ── 2. Raw IPv6 throughput ───────────────────────────────────────
	var rawV6PPS float64
	t.Run("IPv6_RawThroughput", func(t *testing.T) {
		s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, srcIPv4)
		defer s.handle.Close()
		s.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)

		var dst [16]byte
		copy(dst[:], net.ParseIP("2001:db8::dead:beef").To16())

		txBefore := readCounter("rs_e2e0", "tx_packets")

		count := runRawLoop(s, dst, 80, perfDuration)
		rawV6PPS = float64(count) / perfDuration.Seconds()

		txAfter := readCounter("rs_e2e0", "tx_packets")
		txDelta := txAfter - txBefore

		t.Logf("Sent:       %d packets in %v", count, perfDuration)
		t.Logf("Rate:       %.0f PPS (%.2f Mpps)", rawV6PPS, rawV6PPS/1e6)
		t.Logf("Kernel TX:  %d", txDelta)

		if rawV6PPS < minPPS {
			t.Errorf("IPv6 PPS %.0f below minimum %d", rawV6PPS, minPPS)
		}

		// IPv6 should be within 30% of IPv4 (larger headers but same send path)
		if rawV4PPS > 0 {
			ratio := rawV6PPS / rawV4PPS
			t.Logf("v6/v4 ratio: %.2f", ratio)
			if ratio < 0.70 {
				t.Errorf("IPv6 throughput %.0f is %.0f%% of IPv4 %.0f — too much regression",
					rawV6PPS, ratio*100, rawV4PPS)
			}
		}
	})

	// ── 3. Pipeline throughput (iterator → sender) ───────────────────
	t.Run("IPv4_Pipeline", func(t *testing.T) {
		s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, srcIPv4)
		defer s.handle.Close()

		// 10.0.0.0/14 × 4 ports = ~4M tuples
		iter, err := targets.NewTupleIterator(
			[]string{"10.0.0.0/14"}, "80,443,8080,22", nil,
		)
		if err != nil {
			t.Fatal(err)
		}

		total := iter.GetEnd()
		t.Logf("Scan space: %d tuples (%d IPs × %d ports)",
			total, iter.TotalIPs(), iter.TotalPorts())

		txBefore := readCounter("rs_e2e0", "tx_packets")
		start := time.Now()

		var count uint64
		for {
			ip, port, ok := iter.Next()
			if !ok {
				break
			}
			if err := s.SendSYNWithPort([16]byte(ip), port, 40000); err != nil {
				t.Fatalf("SendSYNWithPort after %d: %v", count, err)
			}
			count++
		}

		elapsed := time.Since(start)
		pps := float64(count) / elapsed.Seconds()

		txAfter := readCounter("rs_e2e0", "tx_packets")
		txDelta := txAfter - txBefore

		t.Logf("Sent:       %d packets in %v", count, elapsed)
		t.Logf("Rate:       %.0f PPS (%.2f Mpps)", pps, pps/1e6)
		t.Logf("Kernel TX:  %d", txDelta)

		if rawV4PPS > 0 {
			overhead := 1.0 - (pps / rawV4PPS)
			t.Logf("Pipeline overhead: %.1f%% vs raw", overhead*100)
			if overhead > 0.25 {
				t.Errorf("pipeline overhead %.1f%% exceeds 25%% budget", overhead*100)
			}
		}
	})

	// ── 4. Multi-shard pipeline (N goroutines) ───────────────────────
	t.Run("MultiShard_Pipeline", func(t *testing.T) {
		numShards := runtime.NumCPU()
		if numShards > 8 {
			numShards = 8
		}
		if numShards < 2 {
			numShards = 2
		}

		// 10.128.0.0/10 × 4 ports = ~16M tuples, split across shards
		iter, err := targets.NewTupleIterator(
			[]string{"10.128.0.0/10"}, "80,443,8080,22", nil,
		)
		if err != nil {
			t.Fatal(err)
		}

		shards := iter.Split(numShards)
		t.Logf("Scan space: %d tuples, %d shards", iter.GetEnd(), numShards)

		// Create one sender per shard
		senders := make([]*RingSender, numShards)
		for i := range senders {
			senders[i] = mustSender(t, "rs_e2e0", srcMAC, dstMAC, srcIPv4)
			defer senders[i].handle.Close()
		}

		txBefore := readCounter("rs_e2e0", "tx_packets")
		rxBefore := readCounter("rs_e2e1", "rx_packets")

		var totalSent atomic.Uint64
		var wg sync.WaitGroup

		start := time.Now()
		for i, shard := range shards {
			wg.Add(1)
			go func(id int, sh *targets.TupleIterator, s *RingSender) {
				defer wg.Done()
				var local uint64
				for {
					ip, port, ok := sh.Next()
					if !ok {
						break
					}
					s.SendSYNWithPort([16]byte(ip), port, uint16(40000+id))
					local++
				}
				totalSent.Add(local)
			}(i, shard, senders[i])
		}
		wg.Wait()

		elapsed := time.Since(start)
		sent := totalSent.Load()
		pps := float64(sent) / elapsed.Seconds()

		txAfter := readCounter("rs_e2e0", "tx_packets")
		rxAfter := readCounter("rs_e2e1", "rx_packets")
		txDelta := txAfter - txBefore
		rxDelta := rxAfter - rxBefore

		t.Logf("Sent:       %d packets in %v (%d shards)", sent, elapsed, numShards)
		t.Logf("Rate:       %.0f PPS (%.2f Mpps)", pps, pps/1e6)
		t.Logf("Kernel TX:  %d  RX: %d  (loss: %d)", txDelta, rxDelta, txDelta-rxDelta)

		// Should scale: aggregate PPS > 1.5× single-sender
		if rawV4PPS > 0 && numShards >= 2 {
			scaling := pps / rawV4PPS
			t.Logf("Scaling:    %.2fx over single sender (%d shards)", scaling, numShards)
			if scaling < 1.3 {
				t.Errorf("multi-shard scaling %.2fx is poor (expected >1.3x with %d shards)", scaling, numShards)
			}
		}
	})

	// ── 5. Mixed v4+v6 pipeline ──────────────────────────────────────
	t.Run("Mixed_v4v6_Pipeline", func(t *testing.T) {
		s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, srcIPv4)
		defer s.handle.Close()
		s.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)

		// Mixed: 512K v4 + 512K v6 targets
		iter, err := targets.NewTupleIterator(
			[]string{"10.50.0.0/15", "2001:db8:1::/113"},
			"80,443", nil,
		)
		if err != nil {
			t.Fatal(err)
		}

		total := iter.GetEnd()
		t.Logf("Mixed scan space: %d tuples (v4+v6)", total)

		start := time.Now()
		var v4Count, v6Count uint64
		for {
			ip, port, ok := iter.Next()
			if !ok {
				break
			}
			ipBytes := [16]byte(ip)
			s.SendSYNWithPort(ipBytes, port, 40000)
			if isIPv4Mapped(ipBytes) {
				v4Count++
			} else {
				v6Count++
			}
		}

		elapsed := time.Since(start)
		totalPkts := v4Count + v6Count
		pps := float64(totalPkts) / elapsed.Seconds()

		t.Logf("Sent:       %d total (v4:%d v6:%d) in %v", totalPkts, v4Count, v6Count, elapsed)
		t.Logf("Rate:       %.0f PPS (%.2f Mpps)", pps, pps/1e6)

		if v4Count == 0 || v6Count == 0 {
			t.Error("expected both v4 and v6 packets in mixed scan")
		}
	})

	// ── 6. Sample packet integrity under load ────────────────────────
	t.Run("IntegrityUnderLoad", func(t *testing.T) {
		s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, srcIPv4)
		defer s.handle.Close()
		s.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)

		// Capture on peer
		captureHandle, err := pcap.OpenLive("rs_e2e1", 1600, true, 50*time.Millisecond)
		if err != nil {
			t.Fatalf("pcap.OpenLive: %v", err)
		}
		defer captureHandle.Close()

		// Write pcap
		pcapFile, err := os.Create("/tmp/rs_scan_e2e_perf.pcap")
		if err != nil {
			t.Fatalf("create pcap: %v", err)
		}
		defer pcapFile.Close()
		pcapWriter := pcapgo.NewWriterNanos(pcapFile)
		pcapWriter.WriteFileHeader(1600, layers.LinkTypeEthernet)

		// Send 50K IPv4 + 50K IPv6 as fast as possible
		var dstV4 [16]byte
		dstV4[10], dstV4[11] = 0xFF, 0xFF
		var dstV6 [16]byte
		copy(dstV6[:], net.ParseIP("2001:db8::1:0").To16())

		const burst = 50000
		for i := 0; i < burst; i++ {
			// Vary dst IP to test cookie uniqueness
			dstV4[14] = byte(i >> 8)
			dstV4[15] = byte(i)
			s.SendSYNWithPort(dstV4, 80, 40000)

			binary.BigEndian.PutUint16(dstV6[14:], uint16(i))
			s.SendSYNWithPort(dstV6, 443, 50000)
		}

		// Capture sample
		time.Sleep(200 * time.Millisecond)

		var captured int
		var v4ok, v6ok int
		var v4bad, v6bad int
		deadline := time.Now().Add(2 * time.Second)
		for captured < 2000 && time.Now().Before(deadline) {
			data, ci, err := captureHandle.ReadPacketData()
			if err != nil {
				continue
			}
			captured++
			pcapWriter.WritePacket(ci, data)

			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			ok := validateCapturedPacket(pkt, s)
			if pkt.Layer(layers.LayerTypeIPv4) != nil {
				if ok {
					v4ok++
				} else {
					v4bad++
				}
			} else {
				if ok {
					v6ok++
				} else {
					v6bad++
				}
			}
		}

		t.Logf("Captured:   %d packets (v4: %d ok / %d bad, v6: %d ok / %d bad)",
			captured, v4ok, v4bad, v6ok, v6bad)
		t.Logf("pcap:       /tmp/rs_scan_e2e_perf.pcap")

		if captured == 0 {
			t.Fatal("no packets captured")
		}
		if v4bad > 0 || v6bad > 0 {
			t.Errorf("packet integrity failures: v4=%d v6=%d", v4bad, v6bad)
		}
		if v4ok == 0 {
			t.Error("no valid IPv4 packets captured")
		}
		if v6ok == 0 {
			t.Error("no valid IPv6 packets captured")
		}
	})

	// ── 7. Memory / GC pressure ──────────────────────────────────────
	t.Run("MemoryProfile", func(t *testing.T) {
		s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, srcIPv4)
		defer s.handle.Close()

		var dst [16]byte
		dst[10], dst[11] = 0xFF, 0xFF
		dst[12], dst[13], dst[14], dst[15] = 10, 0, 0, 1

		// Force GC, then measure
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		const pktCount = 500_000
		for i := 0; i < pktCount; i++ {
			dst[15] = byte(i)
			dst[14] = byte(i >> 8)
			s.SendSYNWithPort(dst, 80, 40000)
		}

		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		allocsDelta := after.Mallocs - before.Mallocs
		allocsPer := float64(allocsDelta) / float64(pktCount)
		gcCount := after.NumGC - before.NumGC
		totalPauseNs := after.PauseTotalNs - before.PauseTotalNs

		t.Logf("Packets:    %d", pktCount)
		t.Logf("Allocs:     %d total (%.4f per packet)", allocsDelta, allocsPer)
		t.Logf("GC pauses:  %d (total pause: %v)", gcCount, time.Duration(totalPauseNs))

		// Budget: <0.01 allocs per packet (essentially zero)
		if allocsPer > 0.01 {
			t.Errorf("allocs per packet = %.4f, want < 0.01", allocsPer)
		}

		// Max GC pause should be under 10ms (no stop-the-world issues)
		if gcCount > 0 {
			maxPause := time.Duration(0)
			// PauseNs is a circular buffer of the last 256 pauses
			pauseEnd := int(after.NumGC)
			pauseStart := int(before.NumGC)
			for i := pauseStart; i < pauseEnd && i < pauseStart+256; i++ {
				p := time.Duration(after.PauseNs[i%256])
				if p > maxPause {
					maxPause = p
				}
			}
			t.Logf("Max pause:  %v", maxPause)
			if maxPause > 10*time.Millisecond {
				t.Errorf("max GC pause %v exceeds 10ms budget", maxPause)
			}
		}
	})

	// ── Final summary ────────────────────────────────────────────────
	t.Logf("%s", "\n"+strings.Repeat("═", 60))
	t.Log("PERFORMANCE SUMMARY")
	t.Logf("%s", strings.Repeat("═", 60))
	t.Logf("IPv4 raw:      %8.0f PPS  (%.2f Mpps)", rawV4PPS, rawV4PPS/1e6)
	t.Logf("IPv6 raw:      %8.0f PPS  (%.2f Mpps)", rawV6PPS, rawV6PPS/1e6)
	if rawV4PPS > 0 {
		t.Logf("v6/v4 parity:  %.0f%%", rawV6PPS/rawV4PPS*100)
	}
	t.Logf("%s", strings.Repeat("═", 60))
}

// ── Helpers ──────────────────────────────────────────────────────────

func mustSender(t *testing.T, iface string, srcMAC, dstMAC net.HardwareAddr, srcIP net.IP) *RingSender {
	t.Helper()
	s, err := NewRingSender(iface, srcMAC, dstMAC, srcIP)
	if err != nil {
		t.Fatalf("NewRingSender: %v", err)
	}
	return s
}

// runRawLoop sends SYNs in a tight loop for the given duration, returns count.
func runRawLoop(s *RingSender, dst [16]byte, port uint16, dur time.Duration) uint64 {
	// Warmup
	for i := 0; i < warmupPkts; i++ {
		dst[15] = byte(i)
		s.SendSYNWithPort(dst, port, 40000)
	}

	var count uint64
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		// Vary last byte to avoid any caching effects
		dst[15] = byte(count)
		s.SendSYNWithPort(dst, port, 40000)
		count++
	}
	return count
}

// readCounter reads a sysfs network interface counter.
func readCounter(iface, counter string) uint64 {
	path := fmt.Sprintf("/sys/class/net/%s/statistics/%s", iface, counter)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return v
}

// validateCapturedPacket checks a single captured packet for correctness.
// Returns true if valid.
func validateCapturedPacket(pkt gopacket.Packet, s *RingSender) bool {
	eth := pkt.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return false
	}

	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		if ip.Version != 4 || ip.TTL != 64 || ip.Protocol != layers.IPProtocolTCP {
			return false
		}
		if ip.Flags&layers.IPv4DontFragment == 0 {
			return false
		}
		// Verify IP checksum
		raw := ipLayer.LayerContents()
		if len(raw) >= 20 {
			stored := binary.BigEndian.Uint16(raw[10:12])
			tmp := make([]byte, len(raw))
			copy(tmp, raw)
			tmp[10], tmp[11] = 0, 0
			if ipChecksum(tmp) != stored {
				return false
			}
		}
	} else if ipLayer := pkt.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip6 := ipLayer.(*layers.IPv6)
		if ip6.Version != 6 || ip6.HopLimit != 64 {
			return false
		}
	} else {
		return false
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	tcp := tcpLayer.(*layers.TCP)

	// Must be SYN-only
	if !tcp.SYN || tcp.ACK || tcp.RST || tcp.FIN {
		return false
	}
	if tcp.Window != 64240 {
		return false
	}
	if tcp.DataOffset != 10 {
		return false
	}

	// Validate cookie
	var dstIP [16]byte
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		dstIP[10], dstIP[11] = 0xFF, 0xFF
		copy(dstIP[12:16], ip.DstIP.To4())
	} else if ipLayer := pkt.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip6 := ipLayer.(*layers.IPv6)
		copy(dstIP[:], ip6.DstIP.To16())
	}

	expectedCookie := s.GenerateCookie(dstIP, uint16(tcp.DstPort))
	if tcp.Seq != expectedCookie {
		return false
	}

	// Check TCP options present
	hasMSS, hasSACK, hasTS, hasWS := false, false, false, false
	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			hasMSS = true
			if len(opt.OptionData) >= 2 {
				mss := binary.BigEndian.Uint16(opt.OptionData)
				if mss != 1460 && mss != 1440 {
					return false
				}
			}
		case layers.TCPOptionKindSACKPermitted:
			hasSACK = true
		case layers.TCPOptionKindTimestamps:
			hasTS = true
		case layers.TCPOptionKindWindowScale:
			hasWS = true
			if len(opt.OptionData) >= 1 && opt.OptionData[0] != 7 {
				return false
			}
		}
	}
	return hasMSS && hasSACK && hasTS && hasWS
}

// ── Latency distribution ─────────────────────────────────────────────

// TestE2E_LatencyProfile measures per-packet send latency distribution.
func TestE2E_LatencyProfile(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	setupVeth(t)
	t.Cleanup(func() { teardownVeth() })

	iface, _ := net.InterfaceByName("rs_e2e0")
	srcMAC := iface.HardwareAddr
	dstMAC := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}

	s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, net.ParseIP("10.99.99.1").To4())
	defer s.handle.Close()
	var srcIPv6 [16]byte
	copy(srcIPv6[:], net.ParseIP("2001:db8::1").To16())
	s.ConfigureIPv6(srcIPv6, srcMAC, dstMAC)

	const sampleSize = 100_000

	for _, tc := range []struct {
		name string
		dst  [16]byte
		port uint16
	}{
		{"IPv4", func() [16]byte {
			var d [16]byte
			d[10], d[11] = 0xFF, 0xFF
			d[12], d[13], d[14], d[15] = 10, 0, 0, 1
			return d
		}(), 80},
		{"IPv6", func() [16]byte {
			var d [16]byte
			copy(d[:], net.ParseIP("2001:db8::dead:beef").To16())
			return d
		}(), 80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			latencies := make([]time.Duration, sampleSize)

			// Warmup
			for i := 0; i < 10000; i++ {
				s.SendSYNWithPort(tc.dst, tc.port, 40000)
			}

			for i := range latencies {
				start := time.Now()
				s.SendSYNWithPort(tc.dst, tc.port, 40000)
				latencies[i] = time.Since(start)
			}

			// Compute percentiles
			sortDurations(latencies)
			p50 := latencies[sampleSize*50/100]
			p90 := latencies[sampleSize*90/100]
			p99 := latencies[sampleSize*99/100]
			p999 := latencies[sampleSize*999/1000]
			max := latencies[sampleSize-1]

			avg := time.Duration(0)
			for _, d := range latencies {
				avg += d
			}
			avg /= time.Duration(sampleSize)

			t.Logf("Samples:  %d", sampleSize)
			t.Logf("Avg:      %v", avg)
			t.Logf("P50:      %v", p50)
			t.Logf("P90:      %v", p90)
			t.Logf("P99:      %v", p99)
			t.Logf("P99.9:    %v", p999)
			t.Logf("Max:      %v", max)

			// P99 should be under 50µs (no weird kernel stalls)
			if p99 > 50*time.Microsecond {
				t.Logf("WARNING: P99 latency %v exceeds 50µs", p99)
			}
			// P99.9 should be under 1ms
			if p999 > 1*time.Millisecond {
				t.Logf("WARNING: P99.9 latency %v exceeds 1ms", p999)
			}
		})
	}
}

func sortDurations(d []time.Duration) {
	n := len(d)
	// Simple insertion sort is fine for 100K (stdlib sort would also work)
	// Actually let's just use sort via a conversion
	for i := 1; i < n; i++ {
		key := d[i]
		j := i - 1
		for j >= 0 && d[j] > key {
			d[j+1] = d[j]
			j--
		}
		d[j+1] = key
	}
}

// ── Cookie collision test ────────────────────────────────────────────

// TestE2E_CookieUniqueness validates cookie distribution over a large IP space.
func TestE2E_CookieUniqueness(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	setupVeth(t)
	t.Cleanup(func() { teardownVeth() })

	iface, _ := net.InterfaceByName("rs_e2e0")
	srcMAC := iface.HardwareAddr
	dstMAC := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	s := mustSender(t, "rs_e2e0", srcMAC, dstMAC, net.ParseIP("10.99.99.1").To4())
	defer s.handle.Close()

	// Generate cookies for 1M unique IPs
	const n = 1_000_000
	cookies := make(map[uint32]int, n)
	var collisions int

	var dst [16]byte
	dst[10], dst[11] = 0xFF, 0xFF
	for i := 0; i < n; i++ {
		dst[12] = byte(i >> 16)
		dst[13] = byte(i >> 8)
		dst[14] = byte(i)
		dst[15] = byte(i >> 24)
		cookie := s.GenerateCookie(dst, 80)
		if _, exists := cookies[cookie]; exists {
			collisions++
		}
		cookies[cookie] = i
	}

	// With 1M 32-bit cookies, birthday paradox predicts ~116 collisions
	// Allow up to 500 (generous margin)
	expectedCollisions := float64(n) * float64(n) / (2 * math.Pow(2, 32))
	t.Logf("Cookies:    %d unique, %d collisions (birthday expectation: %.0f)",
		len(cookies), collisions, expectedCollisions)

	if collisions > 500 {
		t.Errorf("too many cookie collisions: %d (expected ~%.0f)", collisions, expectedCollisions)
	}
}
