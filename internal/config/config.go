package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration structure.
type Config struct {
	Scan   ScanConfig   `yaml:"scan"`
	Output OutputConfig `yaml:"output"`
}

// ScanConfig holds all settings related to the scanning process.
type ScanConfig struct {
	Targets    TargetsConfig `yaml:"targets"`
	Ports      string        `yaml:"ports"`       // e.g., "22,80,443,8000-8100" (supports T:/U: prefix)
	Interface  string        `yaml:"interface"`    // Network interface
	Mode       string        `yaml:"mode"`         // "syn", "udp", "both"
	Rate       int           `yaml:"rate"`         // Packets per second
	Shards     int           `yaml:"shards"`       // Sender threads
	BannerGrab bool          `yaml:"banner_grab"`  // Enable banner grabbing
	Timeout    Duration      `yaml:"timeout"`      // Connection timeout
	Retries    int           `yaml:"retries"`      // UDP retransmit count
	ArenaSlots int           `yaml:"arena_slots"`  // Max concurrent banner grabs
	Sequential bool          `yaml:"sequential"`   // Disable randomization
	SourceIP   string        `yaml:"source_ip"`    // Source IP override
	GwMAC      string        `yaml:"gw_mac"`       // Gateway MAC override
	Probes     string        `yaml:"probes"`       // Probe directory path
}

// TargetsConfig defines included and excluded target sources.
type TargetsConfig struct {
	Include []string `yaml:"include"` // CIDR, IP, or range
	Exclude []string `yaml:"exclude"` // CIDR, IP, or range
}

// OutputConfig controls how results are reported.
type OutputConfig struct {
	File     string         `yaml:"file"`      // JSON output file
	Grepable string         `yaml:"grepable"`  // Grepable output file
	Stdout   bool           `yaml:"stdout"`    // Stream JSONL to stdout
	Webhook  *WebhookOutput `yaml:"webhook"`   // Webhook HTTP POST sink
	OpenOnly bool           `yaml:"open_only"` // Only log open/banner results
	Verbose  bool           `yaml:"verbose"`   // Log timeouts
	Debug    bool           `yaml:"debug"`     // Packet-level diagnostics
	Quiet    bool           `yaml:"quiet"`     // Silent mode
	NoTUI    bool           `yaml:"no_tui"`    // Disable TUI
}

// WebhookOutput configures the webhook output sink.
type WebhookOutput struct {
	URL        string            `yaml:"url"`
	BatchSize  int               `yaml:"batch_size"`
	Timeout    Duration          `yaml:"timeout"`
	MaxRetries int               `yaml:"max_retries"`
	Headers    map[string]string `yaml:"headers"`
}

// Duration wraps time.Duration for YAML unmarshalling from strings like "5s", "10m".
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// LoadConfig reads a YAML configuration file from the specified path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
