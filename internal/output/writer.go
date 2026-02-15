package output

import (
	"encoding/json"
	"io"
	"os"
	"sync"
)

// Writer handles direct writing of results.
type Writer struct {
	file    *os.File
	mu      sync.Mutex
	encoder *json.Encoder
}

// NewWriter creates a new output writer that writes directly to disk.
func NewWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Writer{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// Write adds a result to the file immediately.
func (w *Writer) Write(res *Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.encoder.Encode(res)
}

// Flush is a no-op now but kept for interface compatibility.
func (w *Writer) Flush() error {
	return w.file.Sync()
}

// Close closes the file.
func (w *Writer) Close() error {
	w.Flush()
	return w.file.Close()
}

// FormattedWriter wraps a file and a Formatter for non-JSON output formats.
type FormattedWriter struct {
	file *os.File
	fmt  Formatter
	mu   sync.Mutex
}

// NewFormattedWriter creates a writer with a specific formatter.
func NewFormattedWriter(path string, f Formatter) (*FormattedWriter, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &FormattedWriter{file: file, fmt: f}, nil
}

func (w *FormattedWriter) Write(res *Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fmt.Write(res)
}

func (w *FormattedWriter) Close() error {
	w.fmt.Flush()
	return w.file.Close()
}

// ClosingWriter wraps a Formatter with a mutex and an io.Closer (typically a file).
type ClosingWriter struct {
	fmt    Formatter
	closer io.Closer
	mu     sync.Mutex
}

// NewClosingWriter creates a ResultWriter that closes the underlying resource on Close.
func NewClosingWriter(f Formatter, c io.Closer) *ClosingWriter {
	return &ClosingWriter{fmt: f, closer: c}
}

func (w *ClosingWriter) Write(res *Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fmt.Write(res)
}

func (w *ClosingWriter) Close() error {
	w.mu.Lock()
	w.fmt.Flush()
	w.mu.Unlock()
	return w.closer.Close()
}

// OutputSink fans out results to multiple writers.
type OutputSink struct {
	writers []ResultWriter
}

// ResultWriter is the interface for anything that accepts results.
type ResultWriter interface {
	Write(res *Result) error
}

func NewOutputSink() *OutputSink {
	return &OutputSink{}
}

func (s *OutputSink) Add(w ResultWriter) {
	s.writers = append(s.writers, w)
}

func (s *OutputSink) Write(res *Result) error {
	for _, w := range s.writers {
		if err := w.Write(res); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all writers that implement io.Closer.
func (s *OutputSink) Close() error {
	var firstErr error
	for _, w := range s.writers {
		if c, ok := w.(io.Closer); ok {
			if err := c.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}