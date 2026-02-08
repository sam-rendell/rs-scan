package limiter

import (
	"time"
)

// TokenBucket implements a high-performance rate limiter using integer nanosecond arithmetic.
// Avoids float64 accumulation drift over long scans.
type TokenBucket struct {
	rateNsPerToken int64 // Nanoseconds per token (1e9 / rate)
	bucketSize     int64 // Maximum tokens
	tokens         int64
	lastCheck      int64 // UnixNano
}

// NewTokenBucket creates a limiter with the given rate (pps) and burst size.
func NewTokenBucket(rate float64, burst float64) *TokenBucket {
	nsPerToken := int64(1e9 / rate)
	if nsPerToken < 1 {
		nsPerToken = 1
	}
	burstInt := int64(burst)
	if burstInt < 1 {
		burstInt = 1
	}
	return &TokenBucket{
		rateNsPerToken: nsPerToken,
		bucketSize:     burstInt,
		tokens:         burstInt,
		lastCheck:      time.Now().UnixNano(),
	}
}

// Wait blocks until n tokens are available.
func (tb *TokenBucket) Wait(n int) {
	needed := int64(n)

	now := time.Now().UnixNano()
	elapsed := now - tb.lastCheck
	tb.lastCheck = now

	tb.tokens += elapsed / tb.rateNsPerToken
	if tb.tokens > tb.bucketSize {
		tb.tokens = tb.bucketSize
	}

	if tb.tokens >= needed {
		tb.tokens -= needed
		return
	}

	// Must wait — sleep for exactly the deficit, then consume everything.
	missing := needed - tb.tokens
	time.Sleep(time.Duration(missing * tb.rateNsPerToken))
	tb.tokens = 0
	tb.lastCheck = time.Now().UnixNano()
}
