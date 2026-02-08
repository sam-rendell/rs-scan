package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration structure.
type Config struct {
	Scan   ScanConfig   `yaml:"scan"`
	Output OutputConfig `yaml:"output"`
}

// ScanConfig holds all settings related to the scanning process.
type ScanConfig struct {
	Targets     TargetsConfig     `yaml:"targets"`
	Ports       string            `yaml:"ports"` // e.g., "22,80,443,8000-8100"
	Performance PerformanceConfig `yaml:"performance"`
	Behavior    BehaviorConfig    `yaml:"behavior"`
	Fingerprint FingerprintConfig `yaml:"fingerprint"`
}

// TargetsConfig defines included and excluded target sources.
type TargetsConfig struct {
	Include []string `yaml:"include"` // CIDR, Range, or file://
	Exclude []string `yaml:"exclude"` // CIDR, Range, or file://
}

// PerformanceConfig controls rate limiting and concurrency.
type PerformanceConfig struct {
	PPS       int    `yaml:"pps"`       // Packets Per Second
	Kbps      int    `yaml:"kbps"`      // Bandwidth limit
	Shards    int    `yaml:"shards"`    // Number of threads
	SourceIP  string `yaml:"source_ip"` // "auto" or explicit IP
	Interface string `yaml:"interface"` // Network interface
}

// BehaviorConfig defines the type of scan.
type BehaviorConfig struct {
	Type       string `yaml:"type"`        // "syn", "udp", "xmas", "fin"
	BannerGrab bool   `yaml:"banner_grab"` // True to complete handshake
	DryRun     bool   `yaml:"dry_run"`     // True to simulate only
}

// FingerprintConfig controls passive OS fingerprinting.
type FingerprintConfig struct {
	Enabled   bool `yaml:"enabled"`
	StorePCAP bool `yaml:"store_pcap"`
}

// OutputConfig controls how results are reported.
type OutputConfig struct {
	Format string   `yaml:"format"` // "jsonl", "csv", "binary"
	Fields []string `yaml:"fields"`
	File   string   `yaml:"file"` // Output filename
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
