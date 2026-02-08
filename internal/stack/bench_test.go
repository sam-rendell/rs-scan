package stack

import (
	"testing"
)

func BenchmarkHash4Tuple(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hash4Tuple(0xC0A80001, 0x0A000001, 12345, 80)
	}
}

func BenchmarkAddSynSent(b *testing.B) {
	t := NewConnectionTable()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.AddSynSent(0xC0A80001, uint32(i), uint16(i%60000+1024), 80, uint32(i))
	}
}

func BenchmarkGet_Hit(b *testing.B) {
	t := NewConnectionTable()
	// Pre-populate
	for i := 0; i < 100000; i++ {
		t.AddSynSent(0xC0A80001, uint32(i), uint16(i%60000+1024), 80, uint32(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 100000
		t.Get(0xC0A80001, uint32(idx), uint16(idx%60000+1024), 80)
	}
}

func BenchmarkGet_Miss(b *testing.B) {
	t := NewConnectionTable()
	// Pre-populate with different keys
	for i := 0; i < 100000; i++ {
		t.AddSynSent(0xC0A80001, uint32(i), uint16(i%60000+1024), 80, uint32(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Get(0xDEADBEEF, uint32(i), 9999, 9999)
	}
}

func BenchmarkAddSynSent_Parallel(b *testing.B) {
	t := NewConnectionTable()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := uint32(0)
		for pb.Next() {
			t.AddSynSent(0xC0A80001, i, uint16(i%60000+1024), 80, i)
			i++
		}
	})
}

func BenchmarkGet_Parallel(b *testing.B) {
	t := NewConnectionTable()
	for i := 0; i < 1000000; i++ {
		t.AddSynSent(0xC0A80001, uint32(i), uint16(i%60000+1024), 80, uint32(i))
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			idx := i % 1000000
			t.Get(0xC0A80001, uint32(idx), uint16(idx%60000+1024), 80)
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
		for i := 0; i < size; i++ {
			t.AddSynSent(0xC0A80001, uint32(i), uint16(i%60000+1024), 80, uint32(i))
		}
		b.StartTimer()
		t.Cleanup(0) // timeout=0 expires everything
		b.StopTimer()
	}
}
