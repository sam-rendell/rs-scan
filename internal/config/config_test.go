package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	yamlContent := `
scan:
  targets:
    include:
      - "192.168.0.0/16"
      - "file://targets.txt"
    exclude:
      - "192.168.1.5"
  ports: "80,443"
  performance:
    pps: 1000
    shards: 2
  behavior:
    type: "syn"
    banner_grab: true
output:
  format: "jsonl"
`
	tmpfile, err := os.CreateTemp("", "config_test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(yamlContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(cfg.Scan.Targets.Include) != 2 {
		t.Errorf("Expected 2 include targets, got %d", len(cfg.Scan.Targets.Include))
	}
	if cfg.Scan.Performance.PPS != 1000 {
		t.Errorf("Expected PPS 1000, got %d", cfg.Scan.Performance.PPS)
	}
	if cfg.Scan.Behavior.Type != "syn" {
		t.Errorf("Expected scan type 'syn', got '%s'", cfg.Scan.Behavior.Type)
	}
}
