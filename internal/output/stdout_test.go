package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStdoutWriter_Write(t *testing.T) {
	// Capture stdout via pipe
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	sw := NewStdoutWriter(64) // small threshold to force flush
	sw.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: 80, Proto: "tcp", Timestamp: "2026-01-01T00:00:00Z"})
	sw.Close()
	w.Close()

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Fatal("expected JSONL output on stdout, got empty")
	}

	// Verify it's valid JSON
	var res Result
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &res); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, output)
	}
	if res.IP != "10.0.0.1" {
		t.Errorf("IP: want 10.0.0.1, got %s", res.IP)
	}
}

func TestStdoutWriter_BatchFlush(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	sw := NewStdoutWriter(64)
	// Write multiple results to trigger batch flush
	for i := 0; i < 5; i++ {
		sw.Write(&Result{Event: "OPEN", IP: "10.0.0.1", Port: uint16(80 + i), Proto: "tcp"})
	}
	sw.Close()
	w.Close()

	var buf bytes.Buffer
	buf.ReadFrom(r)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	if len(lines) != 5 {
		t.Fatalf("expected 5 JSONL lines, got %d", len(lines))
	}
}
