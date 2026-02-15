//go:build linux

package sender

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLoopbackThroughput measures raw SYN send throughput on the loopback interface.
// Run with: sudo go test -v -run TestLoopbackThroughput -count=1 -timeout 120s ./internal/sender/
func TestLoopbackThroughput(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (AF_PACKET)")
	}

	iface := "lo"
	srcMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	dstMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	srcIP := net.IP{127, 0, 0, 1}

	// Test 1: Single-thread raw send speed (no rate limit, no conn table)
	t.Run("SingleThread_RawSend", func(t *testing.T) {
		s, err := NewRingSender(iface, srcMAC, dstMAC, srcIP)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		const count = 1_000_000
		start := time.Now()
		for i := range count {
			dstIP := u32ToIP16(0x7F000001)
			dstPort := uint16(80)
			srcPort := uint16(32768 + i%17232)
			s.SendSYNWithPort(dstIP, dstPort, srcPort)
		}
		elapsed := time.Since(start)
		pps := float64(count) / elapsed.Seconds()
		nsPerPkt := float64(elapsed.Nanoseconds()) / float64(count)
		t.Logf("Single thread (gopacket): %.2f M pps (%.0f ns/pkt), %v for %d pkts",
			pps/1e6, nsPerPkt, elapsed, count)
	})

	// Test 2: Multi-thread raw send speed (N senders, separate handles)
	for _, numThreads := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("Threads_%d_RawSend", numThreads), func(t *testing.T) {
			const totalPkts = 4_000_000
			pktsPerThread := totalPkts / numThreads

			var wg sync.WaitGroup
			var totalSent int64
			start := time.Now()

			for thr := range numThreads {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					runtime.LockOSThread()

					s, err := NewRingSender(iface, srcMAC, dstMAC, srcIP)
					if err != nil {
						t.Errorf("thread %d: %v", id, err)
						return
					}
					defer s.Close()

					var sent int64
					for i := range pktsPerThread {
						dstIP := u32ToIP16(uint32(0x7F000001 + i))
						dstPort := uint16(80)
						srcPort := uint16(32768 + i%17232)
						if err := s.SendSYNWithPort(dstIP, dstPort, srcPort); err != nil {
							t.Errorf("thread %d pkt %d: %v", id, i, err)
							return
						}
						sent++
					}
					atomic.AddInt64(&totalSent, sent)
				}(thr)
			}
			wg.Wait()
			elapsed := time.Since(start)

			pps := float64(totalSent) / elapsed.Seconds()
			nsPerPkt := float64(elapsed.Nanoseconds()) / float64(totalSent)
			t.Logf("%d threads (gopacket): %.2f M pps (%.0f ns/pkt), sent %d in %v",
				numThreads, pps/1e6, nsPerPkt, totalSent, elapsed)
		})
	}

	// Test 3: Measure packet building vs write separately
	t.Run("WriteOnly_vs_BuildAndWrite", func(t *testing.T) {
		s, err := NewRingSender(iface, srcMAC, dstMAC, srcIP)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		const count = 1_000_000

		// Measure build-only (no write)
		start := time.Now()
		for i := range count {
			pkt := &s.synPkt
			dstIPu32 := uint32(0x7F000001 + i) // keep for packet patching
			dstIP16 := u32ToIP16(dstIPu32)     // for GenerateCookie
			s.ipID++
			binary.BigEndian.PutUint16(pkt[offIPId:], s.ipID)
			binary.BigEndian.PutUint32(pkt[offIPDstIP:], dstIPu32) // patch template with uint32
			binary.BigEndian.PutUint16(pkt[offIPChecksum:], 0)
			binary.BigEndian.PutUint16(pkt[offIPChecksum:], ipChecksum(pkt[ipOff:ipOff+ipLen]))
			binary.BigEndian.PutUint16(pkt[offTCPSrcPort:], uint16(32768+i%17232))
			binary.BigEndian.PutUint16(pkt[offTCPDstPort:], 80)
			binary.BigEndian.PutUint32(pkt[offTCPSeq:], s.GenerateCookie(dstIP16, 80))
			binary.BigEndian.PutUint16(pkt[offTCPChecksum:], 0)
			binary.BigEndian.PutUint16(pkt[offTCPChecksum:],
				tcpChecksum(pkt[offIPSrcIP:offIPSrcIP+4], pkt[offIPDstIP:offIPDstIP+4], pkt[tcpOff:synPktLen]))
		}
		buildElapsed := time.Since(start)
		buildNs := float64(buildElapsed.Nanoseconds()) / float64(count)

		// Measure build+write
		start = time.Now()
		for i := range count {
			dstIP := u32ToIP16(uint32(0x7F000001 + i))
			srcPort := uint16(32768 + i%17232)
			s.SendSYNWithPort(dstIP, 80, srcPort)
		}
		totalElapsed := time.Since(start)
		totalNs := float64(totalElapsed.Nanoseconds()) / float64(count)

		writeNs := totalNs - buildNs
		t.Logf("Build only:  %.0f ns/pkt (%.2f M pps theoretical)", buildNs, 1e9/buildNs/1e6)
		t.Logf("Build+Write: %.0f ns/pkt (%.2f M pps)", totalNs, 1e9/totalNs/1e6)
		t.Logf("Write alone: ~%.0f ns/pkt (AF_PACKET write() overhead)", writeNs)
	})

	// Test 4: sendmmsg BatchSender — the key optimization
	t.Run("BatchSender_sendmmsg", func(t *testing.T) {
		bs, err := NewBatchSender(iface, srcMAC, dstMAC, srcIP)
		if err != nil {
			t.Fatal(err)
		}
		defer bs.Close()

		const count = 2_000_000
		var totalSent int64
		start := time.Now()
		for i := range count {
			dstIP := u32ToIP16(uint32(0x7F000001 + i))
			srcPort := uint16(32768 + i%17232)
			if bs.QueueSYN(dstIP, 80, srcPort) {
				n, err := bs.Flush()
				if err != nil {
					t.Fatalf("flush at pkt %d: %v", i, err)
				}
				totalSent += int64(n)
			}
		}
		// Flush remainder
		if bs.Count() > 0 {
			n, err := bs.Flush()
			if err != nil {
				t.Fatal(err)
			}
			totalSent += int64(n)
		}
		elapsed := time.Since(start)

		pps := float64(totalSent) / elapsed.Seconds()
		nsPerPkt := float64(elapsed.Nanoseconds()) / float64(totalSent)
		t.Logf("BatchSender (sendmmsg, batch=%d): %.2f M pps (%.0f ns/pkt), sent %d in %v",
			BatchSize, pps/1e6, nsPerPkt, totalSent, elapsed)
	})

	// Test 5: Multi-thread BatchSender
	for _, numThreads := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("Threads_%d_BatchSender", numThreads), func(t *testing.T) {
			const totalPkts = 4_000_000
			pktsPerThread := totalPkts / numThreads

			var wg sync.WaitGroup
			var totalSent int64
			start := time.Now()

			for thr := range numThreads {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					runtime.LockOSThread()

					bs, err := NewBatchSender(iface, srcMAC, dstMAC, srcIP)
					if err != nil {
						t.Errorf("thread %d: %v", id, err)
						return
					}
					defer bs.Close()

					var sent int64
					for i := range pktsPerThread {
						dstIP := u32ToIP16(uint32(0x7F000001 + i))
						srcPort := uint16(32768 + i%17232)
						if bs.QueueSYN(dstIP, 80, srcPort) {
							n, err := bs.Flush()
							if err != nil {
								t.Errorf("thread %d flush: %v", id, err)
								return
							}
							sent += int64(n)
						}
					}
					if bs.Count() > 0 {
						n, err := bs.Flush()
						if err != nil {
							t.Errorf("thread %d final flush: %v", id, err)
							return
						}
						sent += int64(n)
					}
					atomic.AddInt64(&totalSent, sent)
				}(thr)
			}
			wg.Wait()
			elapsed := time.Since(start)

			pps := float64(totalSent) / elapsed.Seconds()
			nsPerPkt := float64(elapsed.Nanoseconds()) / float64(totalSent)
			t.Logf("%d threads (sendmmsg, batch=%d): %.2f M pps (%.0f ns/pkt), sent %d in %v",
				numThreads, BatchSize, pps/1e6, nsPerPkt, totalSent, elapsed)
		})
	}

	// Test 6: TX_RING sender (what masscan uses)
	t.Run("TXRing_sendto", func(t *testing.T) {
		ts, err := NewTXRingSender(iface, srcMAC, dstMAC, srcIP)
		if err != nil {
			t.Fatalf("NewTXRingSender: %v", err)
		}
		defer ts.Close()

		const count = 2_000_000
		var totalSent int64
		start := time.Now()
		for i := range count {
			dstIP := u32ToIP16(uint32(0x7F000001 + i))
			srcPort := uint16(32768 + i%17232)
			if ts.QueueSYN(dstIP, 80, srcPort) {
				n, err := ts.Flush()
				if err != nil {
					t.Fatalf("flush at pkt %d: %v", i, err)
				}
				totalSent += int64(n)
			}
		}
		if ts.Pending() > 0 {
			n, err := ts.Flush()
			if err != nil {
				t.Fatal(err)
			}
			totalSent += int64(n)
		}
		elapsed := time.Since(start)

		pps := float64(totalSent) / elapsed.Seconds()
		nsPerPkt := float64(elapsed.Nanoseconds()) / float64(totalSent)
		t.Logf("TX_RING (batch=%d): %.2f M pps (%.0f ns/pkt), sent %d in %v",
			BatchSize, pps/1e6, nsPerPkt, totalSent, elapsed)
	})

	// Test 7: Multi-thread TX_RING
	for _, numThreads := range []int{2, 4, 8} {
		t.Run(fmt.Sprintf("Threads_%d_TXRing", numThreads), func(t *testing.T) {
			const totalPkts = 4_000_000
			pktsPerThread := totalPkts / numThreads

			var wg sync.WaitGroup
			var totalSent int64
			start := time.Now()

			for thr := range numThreads {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					runtime.LockOSThread()

					ts, err := NewTXRingSender(iface, srcMAC, dstMAC, srcIP)
					if err != nil {
						t.Errorf("thread %d: %v", id, err)
						return
					}
					defer ts.Close()

					var sent int64
					for i := range pktsPerThread {
						dstIP := u32ToIP16(uint32(0x7F000001 + i))
						srcPort := uint16(32768 + i%17232)
						if ts.QueueSYN(dstIP, 80, srcPort) {
							n, err := ts.Flush()
							if err != nil {
								t.Errorf("thread %d flush: %v", id, err)
								return
							}
							sent += int64(n)
						}
					}
					if ts.Pending() > 0 {
						n, err := ts.Flush()
						if err != nil {
							t.Errorf("thread %d final flush: %v", id, err)
							return
						}
						sent += int64(n)
					}
					atomic.AddInt64(&totalSent, sent)
				}(thr)
			}
			wg.Wait()
			elapsed := time.Since(start)

			pps := float64(totalSent) / elapsed.Seconds()
			nsPerPkt := float64(elapsed.Nanoseconds()) / float64(totalSent)
			t.Logf("%d threads TX_RING (batch=%d): %.2f M pps (%.0f ns/pkt), sent %d in %v",
				numThreads, BatchSize, pps/1e6, nsPerPkt, totalSent, elapsed)
		})
	}
}

// TestDummyThroughput tests on dummy0 interface (less kernel overhead than loopback).
func TestDummyThroughput(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (AF_PACKET)")
	}

	iface := "dummy0"
	// Check interface exists
	_, err := net.InterfaceByName(iface)
	if err != nil {
		t.Skipf("dummy0 not available: %v (create with: sudo ip link add dummy0 type dummy && sudo ip link set dummy0 up)", err)
	}

	srcMAC := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02}
	srcIP := net.IP{10, 99, 0, 1}

	// gopacket write() baseline on dummy
	t.Run("gopacket_write", func(t *testing.T) {
		s, err := NewRingSender(iface, srcMAC, dstMAC, srcIP)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		const count = 2_000_000
		start := time.Now()
		for i := range count {
			dstIP := u32ToIP16(uint32(0x0A630001 + i))
			srcPort := uint16(32768 + i%17232)
			s.SendSYNWithPort(dstIP, 80, srcPort)
		}
		elapsed := time.Since(start)
		pps := float64(count) / elapsed.Seconds()
		t.Logf("gopacket write() on dummy0: %.2f M pps (%.0f ns/pkt)",
			pps/1e6, float64(elapsed.Nanoseconds())/float64(count))
	})

	// sendmmsg on dummy
	t.Run("sendmmsg", func(t *testing.T) {
		bs, err := NewBatchSender(iface, srcMAC, dstMAC, srcIP)
		if err != nil {
			t.Fatal(err)
		}
		defer bs.Close()

		const count = 2_000_000
		var totalSent int64
		start := time.Now()
		for i := range count {
			dstIP := u32ToIP16(uint32(0x0A630001 + i))
			srcPort := uint16(32768 + i%17232)
			if bs.QueueSYN(dstIP, 80, srcPort) {
				n, err := bs.Flush()
				if err != nil {
					t.Fatalf("flush: %v", err)
				}
				totalSent += int64(n)
			}
		}
		if bs.Count() > 0 {
			n, _ := bs.Flush()
			totalSent += int64(n)
		}
		elapsed := time.Since(start)
		pps := float64(totalSent) / elapsed.Seconds()
		t.Logf("sendmmsg on dummy0: %.2f M pps (%.0f ns/pkt)",
			pps/1e6, float64(elapsed.Nanoseconds())/float64(totalSent))
	})

	// TX_RING on dummy
	t.Run("txring", func(t *testing.T) {
		ts, err := NewTXRingSender(iface, srcMAC, dstMAC, srcIP)
		if err != nil {
			t.Fatalf("NewTXRingSender: %v", err)
		}
		defer ts.Close()

		const count = 2_000_000
		var totalSent int64
		start := time.Now()
		for i := range count {
			dstIP := u32ToIP16(uint32(0x0A630001 + i))
			srcPort := uint16(32768 + i%17232)
			if ts.QueueSYN(dstIP, 80, srcPort) {
				n, err := ts.Flush()
				if err != nil {
					t.Fatalf("flush: %v", err)
				}
				totalSent += int64(n)
			}
		}
		if ts.Pending() > 0 {
			n, _ := ts.Flush()
			totalSent += int64(n)
		}
		elapsed := time.Since(start)
		pps := float64(totalSent) / elapsed.Seconds()
		t.Logf("TX_RING on dummy0: %.2f M pps (%.0f ns/pkt)",
			pps/1e6, float64(elapsed.Nanoseconds())/float64(totalSent))
	})

	// Multi-thread TX_RING on dummy
	for _, numThreads := range []int{2, 4, 8} {
		t.Run(fmt.Sprintf("Threads_%d_TXRing", numThreads), func(t *testing.T) {
			const totalPkts = 4_000_000
			pktsPerThread := totalPkts / numThreads

			var wg sync.WaitGroup
			var totalSent int64
			start := time.Now()

			for thr := range numThreads {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					runtime.LockOSThread()

					ts, err := NewTXRingSender(iface, srcMAC, dstMAC, srcIP)
					if err != nil {
						t.Errorf("thread %d: %v", id, err)
						return
					}
					defer ts.Close()

					var sent int64
					for i := range pktsPerThread {
						dstIP := u32ToIP16(uint32(0x0A630001 + i))
						srcPort := uint16(32768 + i%17232)
						if ts.QueueSYN(dstIP, 80, srcPort) {
							n, err := ts.Flush()
							if err != nil {
								t.Errorf("thread %d flush: %v", id, err)
								return
							}
							sent += int64(n)
						}
					}
					if ts.Pending() > 0 {
						n, _ := ts.Flush()
						sent += int64(n)
					}
					atomic.AddInt64(&totalSent, sent)
				}(thr)
			}
			wg.Wait()
			elapsed := time.Since(start)

			pps := float64(totalSent) / elapsed.Seconds()
			t.Logf("%d threads TX_RING on dummy0: %.2f M pps (%.0f ns/pkt)",
				numThreads, pps/1e6, float64(elapsed.Nanoseconds())/float64(totalSent))
		})
	}
}
