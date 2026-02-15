package targets

import (
	"testing"
)

func BenchmarkFeistelPermute_256(b *testing.B) {
	perm := NewFeistelPermutation(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		perm.Permute(uint64(i) % 256)
	}
}

func BenchmarkFeistelPermute_1M(b *testing.B) {
	perm := NewFeistelPermutation(1_000_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		perm.Permute(uint64(i) % 1_000_000)
	}
}

func BenchmarkFeistelPermute_4B(b *testing.B) {
	perm := NewFeistelPermutation(4_000_000_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		perm.Permute(uint64(i) % 4_000_000_000)
	}
}

func BenchmarkRoundFunc(b *testing.B) {
	for i := 0; i < b.N; i++ {
		roundFunc(uint64(i), 0xDEADBEEFCAFEBABE)
	}
}

func BenchmarkTupleIteratorNext(b *testing.B) {
	// Silence the fmt.Printf in NewTupleIterator
	iter, err := NewTupleIterator([]string{"10.0.0.0/8"}, "80", nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, port, ok := iter.Next()
		if !ok {
			// Reset iterator for continuous benchmarking
			iter.current = 0
		}
		_ = ip
		_ = port
	}
}

func BenchmarkTupleIteratorNext_MultiRange(b *testing.B) {
	iter, err := NewTupleIterator(
		[]string{"10.0.0.0/16", "172.16.0.0/16", "192.168.0.0/16"},
		"22,80,443,8080",
		nil,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, port, ok := iter.Next()
		if !ok {
			iter.current = 0
		}
		_ = ip
		_ = port
	}
}

func BenchmarkTupleIteratorNext_WithExclusion(b *testing.B) {
	iter, err := NewTupleIterator(
		[]string{"10.0.0.0/8"},
		"80",
		[]string{"10.0.0.0/24", "10.1.0.0/16", "10.128.0.0/9"},
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, port, ok := iter.Next()
		if !ok {
			iter.current = 0
		}
		_ = ip
		_ = port
	}
}

func BenchmarkResolveIP_SingleRange(b *testing.B) {
	iter, _ := NewTupleIterator([]string{"10.0.0.0/8"}, "80", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iter.resolveIP(uint64(i) % iter.totalIPs)
	}
}

func BenchmarkResolveIP_10Ranges(b *testing.B) {
	iter, _ := NewTupleIterator([]string{
		"10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "10.4.0.0/16",
		"10.5.0.0/16", "10.6.0.0/16", "10.7.0.0/16", "10.8.0.0/16", "10.9.0.0/16",
	}, "80", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iter.resolveIP(uint64(i) % iter.totalIPs)
	}
}

func BenchmarkIPToUint32(b *testing.B) {
	ip := []byte{10, 0, 0, 1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IPToUint32(ip)
	}
}

func BenchmarkIntervalTreeContains(b *testing.B) {
	tree := &IntervalTree{}
	// Add 100 exclusion ranges
	for i := uint32(0); i < 100; i++ {
		base := i * 65536
		tree.Insert(base, base+255)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Contains(uint32(i))
	}
}
