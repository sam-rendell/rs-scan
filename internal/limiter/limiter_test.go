package limiter

import (
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	// Rate: 100 per second
	rate := 100.0
	tb := NewTokenBucket(rate, 10) // Burst 10

	start := time.Now()
	count := 0
	
	// Consume 110 tokens. Should take approx 1 second (burst 10 is instant, 100 take 1s).
	// Actually, initial 10 are free. So 100 remaining take 1 second.
	for i := 0; i < 11; i++ {
		tb.Wait(10) // Request batch of 10
		count += 10
	}

	elapsed := time.Since(start).Seconds()
	
	if count != 110 {
		t.Errorf("Expected 110 items, got %d", count)
	}

	// We expect roughly 1.0 seconds. Allow slight variance.
	if elapsed < 0.9 || elapsed > 1.2 {
		t.Errorf("Rate limit failed. Expected ~1.0s, took %f", elapsed)
	}
}
