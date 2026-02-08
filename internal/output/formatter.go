package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Result represents a single found target.
type Result struct {
	Event     string `json:"event"`
	IP        string `json:"ip"`
	Port      uint16 `json:"port"`
	Proto     string `json:"proto"`
	Timestamp string `json:"timestamp"`
	TTL       uint8  `json:"ttl,omitempty"`
	Banner    string `json:"banner,omitempty"`
	// OS Fingerprint (raw TCP/IP signals for external tools)
	Window     uint16 `json:"window,omitempty"`
	MSS        uint16 `json:"mss,omitempty"`
	WScale     uint8  `json:"wscale,omitempty"`
	TCPOptions string `json:"tcp_options,omitempty"` // "M,S,T,N,W" encoded
	DF         bool   `json:"df,omitempty"`
	// OS Guess
	OSFamily     string `json:"os_family,omitempty"`
	OSConfidence string `json:"os_confidence,omitempty"` // "high"/"medium"/"low"
}

type Formatter interface {
	Write(res *Result) error
	Flush() error
}

// JSONFormatter writes JSONL.
type JSONFormatter struct {
	enc *json.Encoder
}

func NewJSONFormatter(w io.Writer) *JSONFormatter {
	return &JSONFormatter{enc: json.NewEncoder(w)}
}

func (f *JSONFormatter) Write(res *Result) error {
	return f.enc.Encode(res)
}

func (f *JSONFormatter) Flush() error { return nil }

// CSVFormatter writes CSV.
type CSVFormatter struct {
	writer *csv.Writer
}

func NewCSVFormatter(w io.Writer) *CSVFormatter {
	cw := csv.NewWriter(w)
	cw.Write([]string{"timestamp", "ip", "port", "ttl", "banner", "window", "mss", "wscale", "tcp_options", "df", "os_family", "os_confidence"})
	return &CSVFormatter{writer: cw}
}

func (f *CSVFormatter) Write(res *Result) error {
	df := ""
	if res.DF {
		df = "1"
	}
	return f.writer.Write([]string{
		res.Timestamp,
		res.IP,
		fmt.Sprintf("%d", res.Port),
		fmt.Sprintf("%d", res.TTL),
		strings.ToValidUTF8(res.Banner, ""),
		fmt.Sprintf("%d", res.Window),
		fmt.Sprintf("%d", res.MSS),
		fmt.Sprintf("%d", res.WScale),
		res.TCPOptions,
		df,
		res.OSFamily,
		res.OSConfidence,
	})
}

func (f *CSVFormatter) Flush() error {
	f.writer.Flush()
	return f.writer.Error()
}

// TextFormatter writes simple text.
type TextFormatter struct {
	w io.Writer
}

func NewTextFormatter(w io.Writer) *TextFormatter {
	return &TextFormatter{w: w}
}

func (f *TextFormatter) Write(res *Result) error {
	banner := ""
	if res.Banner != "" {
		banner = fmt.Sprintf(" | %s", strings.TrimSpace(res.Banner))
	}
	_, err := fmt.Fprintf(f.w, "%s:%d%s\n", res.IP, res.Port, banner)
	return err
}

func (f *TextFormatter) Flush() error { return nil }

// GrepFormatter writes nmap-style grepable output.
type GrepFormatter struct {
	w io.Writer
}

func NewGrepFormatter(w io.Writer) *GrepFormatter {
	return &GrepFormatter{w: w}
}

func (f *GrepFormatter) Write(res *Result) error {
	state := "open"
	switch res.Event {
	case "CLOSED":
		state = "closed"
	case "TIMEOUT":
		state = "open|filtered"
	}
	proto := res.Proto
	if proto == "" {
		proto = "tcp"
	}
	_, err := fmt.Fprintf(f.w, "Host: %s ()\tPorts: %d/%s/%s////\n",
		res.IP, res.Port, state, proto)
	return err
}

func (f *GrepFormatter) Flush() error { return nil }

// MultiWriter supports concurrent writes.
type MultiWriter struct {
	Formatter Formatter
	mu        sync.Mutex
}

func (w *MultiWriter) Write(res *Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Formatter.Write(res)
}

func (w *MultiWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Formatter.Flush()
}
