package output

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// WebhookConfig holds settings for the webhook output sink.
type WebhookConfig struct {
	URL        string
	BatchSize  int
	Timeout    time.Duration
	MaxRetries int
	Headers    map[string]string
}

// WebhookWriter posts batched JSONL to a remote HTTP endpoint.
type WebhookWriter struct {
	batch     *batchWriter
	client    *http.Client
	url       string
	headers   map[string]string
	retries   int
	queue     chan []byte
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex // protects closed
	closed    bool
}

// NewWebhookWriter creates a writer that batches results and POSTs them to url.
func NewWebhookWriter(cfg WebhookConfig) *WebhookWriter {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchThreshold
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}

	w := &WebhookWriter{
		client:  &http.Client{Timeout: cfg.Timeout},
		url:     cfg.URL,
		headers: cfg.Headers,
		retries: cfg.MaxRetries,
		queue:   make(chan []byte, 64),
		done:    make(chan struct{}),
	}

	w.batch = newBatchWriter(cfg.BatchSize, func(data []byte) error {
		// Hold w.mu during the channel send to prevent Close() from
		// closing the channel while we're sending.
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return nil
		}
		// Non-blocking send; drop + warn if queue is full
		select {
		case w.queue <- data:
		default:
			log.Printf("webhook: queue full, dropping %d bytes", len(data))
		}
		w.mu.Unlock()
		return nil
	})

	go w.sender()
	return w
}

func (w *WebhookWriter) sender() {
	defer close(w.done)
	for data := range w.queue {
		w.postWithRetry(data)
	}
}

func (w *WebhookWriter) postWithRetry(data []byte) {
	backoff := 1 * time.Second
	for attempt := 0; attempt < w.retries; attempt++ {
		req, err := http.NewRequest("POST", w.url, bytes.NewReader(data))
		if err != nil {
			log.Printf("webhook: request error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		for k, v := range w.headers {
			req.Header.Set(k, v)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			log.Printf("webhook: POST failed (attempt %d/%d): %v", attempt+1, w.retries, err)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		log.Printf("webhook: POST returned %d (attempt %d/%d)", resp.StatusCode, attempt+1, w.retries)
		time.Sleep(backoff)
		backoff *= 2
	}
	log.Printf("webhook: dropping %d bytes after %d retries", len(data), w.retries)
}

func (w *WebhookWriter) Write(res *Result) error {
	return w.batch.write(res)
}

// Close flushes remaining data and waits for the sender goroutine to drain.
func (w *WebhookWriter) Close() error {
	var err error
	w.closeOnce.Do(func() {
		err = w.batch.close()

		// Mark closed so flushFn from any late write() won't send to queue
		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()

		close(w.queue)
	})

	// Wait for sender goroutine with deadline
	select {
	case <-w.done:
	case <-time.After(30 * time.Second):
		log.Printf("webhook: close timed out waiting for sender")
		return fmt.Errorf("webhook: close timed out")
	}
	return err
}
