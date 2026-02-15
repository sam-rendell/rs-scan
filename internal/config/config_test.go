package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	yamlContent := `
scan:
  targets:
    include:
      - "192.168.0.0/16"
      - "10.0.0.1"
    exclude:
      - "192.168.1.5"
  ports: "T:80,443 U:53,161"
  interface: "eth0"
  mode: "both"
  rate: 5000
  shards: 4
  banner_grab: true
  timeout: "10s"
  retries: 2
  arena_slots: 50000
  sequential: false
  source_ip: "10.0.0.100"
  gw_mac: "aa:bb:cc:dd:ee:ff"
  probes: "/opt/probes"
output:
  file: "results.jsonl"
  grepable: "results.grep"
  open_only: true
  verbose: false
  debug: false
  quiet: false
  no_tui: true
`
	f := writeTempYAML(t, yamlContent)
	defer os.Remove(f)

	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Scan targets
	if len(cfg.Scan.Targets.Include) != 2 {
		t.Errorf("include: want 2, got %d", len(cfg.Scan.Targets.Include))
	}
	if len(cfg.Scan.Targets.Exclude) != 1 {
		t.Errorf("exclude: want 1, got %d", len(cfg.Scan.Targets.Exclude))
	}

	// Scan fields
	if cfg.Scan.Ports != "T:80,443 U:53,161" {
		t.Errorf("ports: want 'T:80,443 U:53,161', got %q", cfg.Scan.Ports)
	}
	if cfg.Scan.Interface != "eth0" {
		t.Errorf("interface: want 'eth0', got %q", cfg.Scan.Interface)
	}
	if cfg.Scan.Mode != "both" {
		t.Errorf("mode: want 'both', got %q", cfg.Scan.Mode)
	}
	if cfg.Scan.Rate != 5000 {
		t.Errorf("rate: want 5000, got %d", cfg.Scan.Rate)
	}
	if cfg.Scan.Shards != 4 {
		t.Errorf("shards: want 4, got %d", cfg.Scan.Shards)
	}
	if !cfg.Scan.BannerGrab {
		t.Error("banner_grab: want true")
	}
	if cfg.Scan.Timeout.Duration != 10*time.Second {
		t.Errorf("timeout: want 10s, got %v", cfg.Scan.Timeout.Duration)
	}
	if cfg.Scan.Retries != 2 {
		t.Errorf("retries: want 2, got %d", cfg.Scan.Retries)
	}
	if cfg.Scan.ArenaSlots != 50000 {
		t.Errorf("arena_slots: want 50000, got %d", cfg.Scan.ArenaSlots)
	}
	if cfg.Scan.SourceIP != "10.0.0.100" {
		t.Errorf("source_ip: want '10.0.0.100', got %q", cfg.Scan.SourceIP)
	}
	if cfg.Scan.GwMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("gw_mac: want 'aa:bb:cc:dd:ee:ff', got %q", cfg.Scan.GwMAC)
	}
	if cfg.Scan.Probes != "/opt/probes" {
		t.Errorf("probes: want '/opt/probes', got %q", cfg.Scan.Probes)
	}

	// Output fields
	if cfg.Output.File != "results.jsonl" {
		t.Errorf("output.file: want 'results.jsonl', got %q", cfg.Output.File)
	}
	if cfg.Output.Grepable != "results.grep" {
		t.Errorf("output.grepable: want 'results.grep', got %q", cfg.Output.Grepable)
	}
	if !cfg.Output.OpenOnly {
		t.Error("output.open_only: want true")
	}
	if cfg.Output.NoTUI != true {
		t.Error("output.no_tui: want true")
	}
}

func TestLoadConfig_Partial(t *testing.T) {
	yamlContent := `
scan:
  targets:
    include:
      - "10.0.0.1"
  ports: "80"
`
	f := writeTempYAML(t, yamlContent)
	defer os.Remove(f)

	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Specified fields
	if cfg.Scan.Ports != "80" {
		t.Errorf("ports: want '80', got %q", cfg.Scan.Ports)
	}
	if len(cfg.Scan.Targets.Include) != 1 {
		t.Errorf("include: want 1, got %d", len(cfg.Scan.Targets.Include))
	}

	// Unspecified fields should be zero values
	if cfg.Scan.Rate != 0 {
		t.Errorf("rate: want 0 (unset), got %d", cfg.Scan.Rate)
	}
	if cfg.Scan.Interface != "" {
		t.Errorf("interface: want '' (unset), got %q", cfg.Scan.Interface)
	}
	if cfg.Scan.BannerGrab {
		t.Error("banner_grab: want false (unset)")
	}
	if cfg.Scan.Timeout.Duration != 0 {
		t.Errorf("timeout: want 0 (unset), got %v", cfg.Scan.Timeout.Duration)
	}
	if cfg.Output.File != "" {
		t.Errorf("output.file: want '' (unset), got %q", cfg.Output.File)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	f := writeTempYAML(t, "{{invalid yaml")
	defer os.Remove(f)

	_, err := LoadConfig(f)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfig_InvalidDuration(t *testing.T) {
	f := writeTempYAML(t, `
scan:
  timeout: "not-a-duration"
`)
	defer os.Remove(f)

	_, err := LoadConfig(f)
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLoadConfig_Webhook(t *testing.T) {
	yamlContent := `
scan:
  targets:
    include:
      - "10.0.0.1"
  ports: "80"
output:
  stdout: true
  webhook:
    url: "https://ingest.example.com/results"
    batch_size: 8192
    timeout: "5s"
    max_retries: 5
    headers:
      Authorization: "Bearer tok123"
      X-Scanner: "rs-scan"
`
	f := writeTempYAML(t, yamlContent)
	defer os.Remove(f)

	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !cfg.Output.Stdout {
		t.Error("output.stdout: want true")
	}
	if cfg.Output.Webhook == nil {
		t.Fatal("output.webhook: want non-nil")
	}
	wh := cfg.Output.Webhook
	if wh.URL != "https://ingest.example.com/results" {
		t.Errorf("webhook.url: got %q", wh.URL)
	}
	if wh.BatchSize != 8192 {
		t.Errorf("webhook.batch_size: want 8192, got %d", wh.BatchSize)
	}
	if wh.Timeout.Duration != 5*time.Second {
		t.Errorf("webhook.timeout: want 5s, got %v", wh.Timeout.Duration)
	}
	if wh.MaxRetries != 5 {
		t.Errorf("webhook.max_retries: want 5, got %d", wh.MaxRetries)
	}
	if wh.Headers["Authorization"] != "Bearer tok123" {
		t.Errorf("webhook.headers.Authorization: got %q", wh.Headers["Authorization"])
	}
	if wh.Headers["X-Scanner"] != "rs-scan" {
		t.Errorf("webhook.headers.X-Scanner: got %q", wh.Headers["X-Scanner"])
	}
}

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}
