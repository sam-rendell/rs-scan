package output

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookWriter_BasicPost(t *testing.T) {
	var received []string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/x-ndjson" {
			t.Errorf("Content-Type: want application/x-ndjson, got %s", ct)
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, string(body))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhookWriter(WebhookConfig{
		URL:       srv.URL,
		BatchSize: 64, // small to trigger flush quickly
	})

	wh.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})
	wh.Close()

	mu.Lock()
	n := len(received)
	mu.Unlock()

	if n == 0 {
		t.Fatal("expected at least one POST, got 0")
	}

	// Verify JSONL content
	mu.Lock()
	body := received[0]
	mu.Unlock()
	if !strings.Contains(body, `"ip":"10.0.0.1"`) {
		t.Errorf("POST body missing expected content: %s", body)
	}
}

func TestWebhookWriter_BatchAccumulation(t *testing.T) {
	var postCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCount, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhookWriter(WebhookConfig{
		URL:       srv.URL,
		BatchSize: 4096, // large batch — accumulate many results
	})

	for i := 0; i < 5; i++ {
		wh.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: uint16(80 + i), Proto: "tcp"})
	}
	wh.Close()

	// 5 small results should fit in one batch
	if n := atomic.LoadInt32(&postCount); n > 3 {
		t.Errorf("expected few POSTs due to batching, got %d", n)
	}
}

func TestWebhookWriter_RetryOnFailure(t *testing.T) {
	var attempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhookWriter(WebhookConfig{
		URL:        srv.URL,
		BatchSize:  64,
		MaxRetries: 3,
	})

	wh.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})
	wh.Close()

	if n := atomic.LoadInt32(&attempts); n < 3 {
		t.Errorf("expected at least 3 attempts (2 failures + 1 success), got %d", n)
	}
}

func TestWebhookWriter_CustomHeaders(t *testing.T) {
	var gotAuth string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhookWriter(WebhookConfig{
		URL:       srv.URL,
		BatchSize: 64,
		Headers:   map[string]string{"Authorization": "Bearer secret-token"},
	})

	wh.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})
	wh.Close()

	mu.Lock()
	auth := gotAuth
	mu.Unlock()

	if auth != "Bearer secret-token" {
		t.Errorf("Authorization header: want 'Bearer secret-token', got %q", auth)
	}
}

func TestWebhookWriter_Close(t *testing.T) {
	var received int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhookWriter(WebhookConfig{
		URL:       srv.URL,
		BatchSize: 1 << 20, // huge — only flush on close
	})

	wh.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})
	wh.Close()

	if n := atomic.LoadInt32(&received); n == 0 {
		t.Fatal("expected pending batch to be sent on Close, got 0")
	}
}

func TestWebhookWriter_DoubleClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhookWriter(WebhookConfig{URL: srv.URL, BatchSize: 64})
	wh.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp"})

	// Double close must not panic
	wh.Close()
	wh.Close()
}

func TestWebhookWriter_ConcurrentWriteClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhookWriter(WebhookConfig{URL: srv.URL, BatchSize: 64})

	// Concurrent writes while close happens
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			wh.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: uint16(i), Proto: "tcp"})
		}
	}()

	// Let some writes happen, then close
	time.Sleep(5 * time.Millisecond)
	wh.Close()
	wg.Wait()
}
