package output

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBatchWriter_ThresholdFlush(t *testing.T) {
	var flushed [][]byte
	var mu sync.Mutex

	bw := newBatchWriter(128, func(data []byte) error {
		mu.Lock()
		cp := make([]byte, len(data))
		copy(cp, data)
		flushed = append(flushed, cp)
		mu.Unlock()
		return nil
	})
	defer bw.close()

	// Write enough results to exceed 128-byte threshold
	for i := 0; i < 10; i++ {
		bw.write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})
	}

	mu.Lock()
	n := len(flushed)
	mu.Unlock()

	if n == 0 {
		t.Fatal("expected at least one flush from threshold, got 0")
	}
}

func TestBatchWriter_TimerFlush(t *testing.T) {
	var flushed int32

	bw := newBatchWriter(1<<20, func(data []byte) error { // huge threshold — won't trigger from size
		atomic.AddInt32(&flushed, 1)
		return nil
	})
	defer bw.close()

	bw.write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})

	// Wait for timer flush (250ms interval + margin)
	time.Sleep(400 * time.Millisecond)

	if atomic.LoadInt32(&flushed) == 0 {
		t.Fatal("expected timer-based flush, got 0")
	}
}

func TestBatchWriter_Close(t *testing.T) {
	var flushed int32

	bw := newBatchWriter(1<<20, func(data []byte) error {
		atomic.AddInt32(&flushed, 1)
		return nil
	})

	bw.write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 443, Proto: "tcp"})
	bw.close()

	if atomic.LoadInt32(&flushed) == 0 {
		t.Fatal("expected final flush on close, got 0")
	}

	// Double close should be safe
	bw.close()
}

func TestBatchWriter_ConcurrentWrite(t *testing.T) {
	var flushCount int32

	bw := newBatchWriter(256, func(data []byte) error {
		atomic.AddInt32(&flushCount, 1)
		return nil
	})

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				bw.write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})
			}
		}()
	}
	wg.Wait()
	bw.close()

	if atomic.LoadInt32(&flushCount) == 0 {
		t.Fatal("expected flushes from concurrent writes, got 0")
	}
}

func TestBatchWriter_WriteAfterClose(t *testing.T) {
	bw := newBatchWriter(1<<20, func(data []byte) error {
		return nil
	})
	bw.close()

	// Write after close should not panic, should be a no-op
	err := bw.write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})
	if err != nil {
		t.Errorf("write after close: want nil error, got %v", err)
	}
}

func TestBatchWriter_EmptyClose(t *testing.T) {
	var flushCount int32
	bw := newBatchWriter(1<<20, func(data []byte) error {
		atomic.AddInt32(&flushCount, 1)
		return nil
	})
	// Close without writing anything
	bw.close()

	if atomic.LoadInt32(&flushCount) != 0 {
		t.Error("expected no flush on empty close")
	}
}
