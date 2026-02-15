package stack

import (
	"testing"
)

func BenchmarkHash4Tuple(b *testing.B) {
	ip1 := u32ToIPAddr(0xC0A80001)
	ip2 := u32ToIPAddr(0x0A000001)
	for i := 0; i < b.N; i++ {
		hash4Tuple(ip1, ip2, 12345, 80)
	}
}

func BenchmarkAddSynSent(b *testing.B) {
	t := NewConnectionTable()
	srcIP := u32ToIPAddr(0xC0A80001)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstIP := u32ToIPAddr(uint32(i))
		t.AddSynSent(srcIP, dstIP, uint16(i%60000+1024), 80, uint32(i))
	}
}

func BenchmarkGet_Hit(b *testing.B) {
	t := NewConnectionTable()
	srcIP := u32ToIPAddr(0xC0A80001)
	// Pre-populate
	for i := 0; i < 100000; i++ {
		dstIP := u32ToIPAddr(uint32(i))
		t.AddSynSent(srcIP, dstIP, uint16(i%60000+1024), 80, uint32(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 100000
		dstIP := u32ToIPAddr(uint32(idx))
		t.Get(srcIP, dstIP, uint16(idx%60000+1024), 80)
	}
}

func BenchmarkGet_Miss(b *testing.B) {
	t := NewConnectionTable()
	srcIP := u32ToIPAddr(0xC0A80001)
	// Pre-populate with different keys
	for i := 0; i < 100000; i++ {
		dstIP := u32ToIPAddr(uint32(i))
		t.AddSynSent(srcIP, dstIP, uint16(i%60000+1024), 80, uint32(i))
	}
	b.ResetTimer()
	missIP := u32ToIPAddr(0xDEADBEEF)
	for i := 0; i < b.N; i++ {
		dstIP := u32ToIPAddr(uint32(i))
		t.Get(missIP, dstIP, 9999, 9999)
	}
}

func BenchmarkAddSynSent_Parallel(b *testing.B) {
	t := NewConnectionTable()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := uint32(0)
		srcIP := u32ToIPAddr(0xC0A80001)
		for pb.Next() {
			dstIP := u32ToIPAddr(i)
			t.AddSynSent(srcIP, dstIP, uint16(i%60000+1024), 80, i)
			i++
		}
	})
}

func BenchmarkGet_Parallel(b *testing.B) {
	t := NewConnectionTable()
	srcIP := u32ToIPAddr(0xC0A80001)
	for i := 0; i < 1000000; i++ {
		dstIP := u32ToIPAddr(uint32(i))
		t.AddSynSent(srcIP, dstIP, uint16(i%60000+1024), 80, uint32(i))
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			idx := i % 1000000
			dstIP := u32ToIPAddr(uint32(idx))
			t.Get(srcIP, dstIP, uint16(idx%60000+1024), 80)
			i++
		}
	})
}

func BenchmarkCleanup_1K(b *testing.B) {
	benchmarkCleanup(b, 1000)
}

func BenchmarkCleanup_100K(b *testing.B) {
	benchmarkCleanup(b, 100000)
}

func benchmarkCleanup(b *testing.B, size int) {
	b.StopTimer()
	for n := 0; n < b.N; n++ {
		t := NewConnectionTable()
		srcIP := u32ToIPAddr(0xC0A80001)
		for i := 0; i < size; i++ {
			dstIP := u32ToIPAddr(uint32(i))
			t.AddSynSent(srcIP, dstIP, uint16(i%60000+1024), 80, uint32(i))
		}
		b.StartTimer()
		t.Cleanup(0) // timeout=0 expires everything
		b.StopTimer()
	}
}
