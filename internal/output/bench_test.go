package output

import (
	"io"
	"testing"
)

func BenchmarkJSONWrite(b *testing.B) {
	w := &Writer{
		file:    nil, // We'll use the encoder directly
	}
	// Create encoder writing to discard
	encoder := newTestEncoder()
	_ = w
	_ = encoder

	// Benchmark the JSON formatter directly
	f := NewJSONFormatter(io.Discard)
	res := &Result{
		Event: "OPEN", IP: "10.0.0.1", Port: 80,
		Timestamp: "2024-01-01T00:00:00Z", TTL: 64,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Write(res)
	}
}

func BenchmarkJSONWriteBanner(b *testing.B) {
	f := NewJSONFormatter(io.Discard)
	res := &Result{
		Event: "BANNER", IP: "10.0.0.1", Port: 22,
		Timestamp: "2024-01-01T00:00:00Z", TTL: 64,
		Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Write(res)
	}
}

func newTestEncoder() interface{} { return nil }
