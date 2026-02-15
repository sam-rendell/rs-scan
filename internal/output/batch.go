package output

import (
	"bytes"
	"encoding/json"
	"log"
	"sync"
	"time"
)

// batchWriter accumulates JSON-encoded results and flushes when the buffer
// exceeds a byte threshold or a periodic timer fires. Write never blocks on I/O.
type batchWriter struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	enc       *json.Encoder
	threshold int
	flushFn   func([]byte) error
	timer     *time.Timer
	closeCh   chan struct{}
	done      chan struct{}
	closed    bool
}

const (
	defaultBatchThreshold = 4096
	batchFlushInterval    = 250 * time.Millisecond
)

func newBatchWriter(threshold int, flushFn func([]byte) error) *batchWriter {
	if threshold <= 0 {
		threshold = defaultBatchThreshold
	}
	bw := &batchWriter{
		threshold: threshold,
		flushFn:   flushFn,
		timer:     time.NewTimer(batchFlushInterval),
		closeCh:   make(chan struct{}),
		done:      make(chan struct{}),
	}
	bw.enc = json.NewEncoder(&bw.buf)
	go bw.run()
	return bw
}

func (bw *batchWriter) run() {
	defer close(bw.done)
	for {
		select {
		case <-bw.closeCh:
			return
		case <-bw.timer.C:
			bw.mu.Lock()
			if bw.buf.Len() > 0 {
				if err := bw.flushLocked(); err != nil {
					log.Printf("batch: timer flush error: %v", err)
				}
			}
			if !bw.closed {
				bw.timer.Reset(batchFlushInterval)
			}
			bw.mu.Unlock()
		}
	}
}

func (bw *batchWriter) write(res *Result) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	if bw.closed {
		return nil
	}
	if err := bw.enc.Encode(res); err != nil {
		return err
	}
	if bw.buf.Len() >= bw.threshold {
		return bw.flushLocked()
	}
	return nil
}

// flushLocked copies buffer, resets it, then calls flushFn outside the lock.
// Caller must hold bw.mu.
func (bw *batchWriter) flushLocked() error {
	if bw.buf.Len() == 0 {
		return nil
	}
	data := make([]byte, bw.buf.Len())
	copy(data, bw.buf.Bytes())
	bw.buf.Reset()
	bw.enc = json.NewEncoder(&bw.buf)

	// Release lock during I/O so concurrent writes aren't blocked.
	bw.mu.Unlock()
	err := bw.flushFn(data)
	bw.mu.Lock()
	return err
}

func (bw *batchWriter) close() error {
	bw.mu.Lock()
	if bw.closed {
		bw.mu.Unlock()
		return nil
	}
	bw.closed = true

	// Stop timer and drain its channel to prevent run() from firing
	// a concurrent flush after we close.
	if !bw.timer.Stop() {
		select {
		case <-bw.timer.C:
		default:
		}
	}
	close(bw.closeCh)

	// Final flush: hold the lock through flushFn to prevent any concurrent
	// flushFn call (the run() goroutine is about to exit via closeCh, and
	// draining the timer prevents it from entering the timer case).
	var err error
	if bw.buf.Len() > 0 {
		data := make([]byte, bw.buf.Len())
		copy(data, bw.buf.Bytes())
		bw.buf.Reset()
		bw.enc = json.NewEncoder(&bw.buf)
		err = bw.flushFn(data)
	}
	bw.mu.Unlock()
	<-bw.done
	return err
}
