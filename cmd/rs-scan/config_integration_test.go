package main

import (
	"testing"
	"time"

	"rs_scan/internal/config"
)

// helper: full config for testing
func fullTestConfig() *config.Config {
	return &config.Config{
		Scan: config.ScanConfig{
			Targets: config.TargetsConfig{
				Include: []string{"10.0.0.0/24"},
				Exclude: []string{"10.0.0.1"},
			},
			Ports:      "22,80,443",
			Interface:  "eth0",
			Mode:       "both",
			Rate:       5000,
			Shards:     4,
			BannerGrab: true,
			Timeout:    config.Duration{Duration: 10 * time.Second},
			Retries:    3,
			ArenaSlots: 50000,
			Sequential: true,
			SourceIP:   "10.0.0.100",
			GwMAC:      "aa:bb:cc:dd:ee:ff",
			Probes:     "/opt/probes",
		},
		Output: config.OutputConfig{
			File:     "results.jsonl",
			Grepable: "results.grep",
			OpenOnly: true,
			Verbose:  true,
			Debug:    true,
			Quiet:    true,
			NoTUI:    true,
		},
	}
}

func TestApplyConfig_AllFieldsApplied(t *testing.T) {
	cfg := fullTestConfig()
	set := map[string]bool{} // nothing set on CLI

	// Initialize with flag defaults
	iface := "wlp0s20f3"
	ports := "80"
	pps := 1000
	shards := 1
	timeout := 5 * time.Second
	retries := 1
	arenaSlots := 100000
	sourceIP := ""
	gwMAC := ""
	probeDir := ""
	outputFile := "output.jsonl"
	oG := ""
	webhookURL := ""
	bannerGrab := false
	sequential := false
	openOnly := false
	verbose := false
	debug := false
	quiet := false
	noTUI := false
	scanSS := false
	scanSU := false

	applyConfig(cfg, set,
		&iface, &ports, &pps, &shards,
		&timeout, &retries, &arenaSlots,
		&sourceIP, &gwMAC, &probeDir,
		&outputFile, &oG, &webhookURL,
		&bannerGrab, &sequential, &openOnly, &verbose, &debug, &quiet, &noTUI,
		&scanSS, &scanSU)

	if iface != "eth0" {
		t.Errorf("iface: want 'eth0', got %q", iface)
	}
	if ports != "22,80,443" {
		t.Errorf("ports: want '22,80,443', got %q", ports)
	}
	if pps != 5000 {
		t.Errorf("pps: want 5000, got %d", pps)
	}
	if shards != 4 {
		t.Errorf("shards: want 4, got %d", shards)
	}
	if timeout != 10*time.Second {
		t.Errorf("timeout: want 10s, got %v", timeout)
	}
	if retries != 3 {
		t.Errorf("retries: want 3, got %d", retries)
	}
	if arenaSlots != 50000 {
		t.Errorf("arena_slots: want 50000, got %d", arenaSlots)
	}
	if sourceIP != "10.0.0.100" {
		t.Errorf("sourceIP: want '10.0.0.100', got %q", sourceIP)
	}
	if gwMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("gwMAC: want 'aa:bb:cc:dd:ee:ff', got %q", gwMAC)
	}
	if probeDir != "/opt/probes" {
		t.Errorf("probeDir: want '/opt/probes', got %q", probeDir)
	}
	if outputFile != "results.jsonl" {
		t.Errorf("outputFile: want 'results.jsonl', got %q", outputFile)
	}
	if oG != "results.grep" {
		t.Errorf("oG: want 'results.grep', got %q", oG)
	}
	if !bannerGrab {
		t.Error("bannerGrab: want true")
	}
	if !sequential {
		t.Error("sequential: want true")
	}
	if !openOnly {
		t.Error("openOnly: want true")
	}
	if !verbose {
		t.Error("verbose: want true")
	}
	if !debug {
		t.Error("debug: want true")
	}
	if !quiet {
		t.Error("quiet: want true")
	}
	if !noTUI {
		t.Error("noTUI: want true")
	}
	if !scanSS {
		t.Error("scanSS: want true (mode=both)")
	}
	if !scanSU {
		t.Error("scanSU: want true (mode=both)")
	}
}

func TestApplyConfig_CLIOverridesConfig(t *testing.T) {
	cfg := fullTestConfig()

	// Simulate CLI flags that were explicitly set
	set := map[string]bool{
		"i":       true,
		"p":       true,
		"pps":     true,
		"shards":  true,
		"timeout": true,
		"retries": true,
		"S":       true,
		"o":       true,
		"open":    true,
		"sS":      true,
	}

	// CLI values (should be preserved)
	iface := "tun0"
	ports := "1-1000"
	pps := 10000
	shards := 8
	timeout := 30 * time.Second
	retries := 5
	arenaSlots := 100000
	sourceIP := "172.16.0.1"
	gwMAC := ""
	probeDir := ""
	outputFile := "cli-output.jsonl"
	oG := ""
	webhookURL := ""
	bannerGrab := false
	sequential := false
	openOnly := true
	verbose := false
	debug := false
	quiet := false
	noTUI := false
	scanSS := true
	scanSU := false

	applyConfig(cfg, set,
		&iface, &ports, &pps, &shards,
		&timeout, &retries, &arenaSlots,
		&sourceIP, &gwMAC, &probeDir,
		&outputFile, &oG, &webhookURL,
		&bannerGrab, &sequential, &openOnly, &verbose, &debug, &quiet, &noTUI,
		&scanSS, &scanSU)

	// These were explicitly set — must keep CLI values
	if iface != "tun0" {
		t.Errorf("iface: CLI override lost, got %q", iface)
	}
	if ports != "1-1000" {
		t.Errorf("ports: CLI override lost, got %q", ports)
	}
	if pps != 10000 {
		t.Errorf("pps: CLI override lost, got %d", pps)
	}
	if shards != 8 {
		t.Errorf("shards: CLI override lost, got %d", shards)
	}
	if timeout != 30*time.Second {
		t.Errorf("timeout: CLI override lost, got %v", timeout)
	}
	if retries != 5 {
		t.Errorf("retries: CLI override lost, got %d", retries)
	}
	if sourceIP != "172.16.0.1" {
		t.Errorf("sourceIP: CLI override lost, got %q", sourceIP)
	}
	if outputFile != "cli-output.jsonl" {
		t.Errorf("outputFile: CLI override lost, got %q", outputFile)
	}
	// scanSS was set, so mode from config shouldn't apply
	if scanSU {
		t.Error("scanSU: should not be set (CLI -sS was explicit)")
	}

	// These were NOT explicitly set — should get config values
	if arenaSlots != 50000 {
		t.Errorf("arenaSlots: want 50000 from config, got %d", arenaSlots)
	}
	if gwMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("gwMAC: want config value, got %q", gwMAC)
	}
	if probeDir != "/opt/probes" {
		t.Errorf("probeDir: want config value, got %q", probeDir)
	}
	if !bannerGrab {
		t.Error("bannerGrab: want true from config")
	}
	if !sequential {
		t.Error("sequential: want true from config")
	}
	if !verbose {
		t.Error("verbose: want true from config")
	}
	if !debug {
		t.Error("debug: want true from config")
	}
	if !quiet {
		t.Error("quiet: want true from config")
	}
	if !noTUI {
		t.Error("noTUI: want true from config")
	}
	if oG != "results.grep" {
		t.Errorf("oG: want config value, got %q", oG)
	}
}

func TestApplyConfig_PartialConfig(t *testing.T) {
	cfg := &config.Config{
		Scan: config.ScanConfig{
			Ports: "443",
			Rate:  2000,
		},
	}
	set := map[string]bool{}

	iface := "wlp0s20f3"
	ports := "80"
	pps := 1000
	shards := 1
	timeout := 5 * time.Second
	retries := 1
	arenaSlots := 100000
	sourceIP := ""
	gwMAC := ""
	probeDir := ""
	outputFile := "output.jsonl"
	oG := ""
	webhookURL := ""
	bannerGrab := false
	sequential := false
	openOnly := false
	verbose := false
	debug := false
	quiet := false
	noTUI := false
	scanSS := false
	scanSU := false

	applyConfig(cfg, set,
		&iface, &ports, &pps, &shards,
		&timeout, &retries, &arenaSlots,
		&sourceIP, &gwMAC, &probeDir,
		&outputFile, &oG, &webhookURL,
		&bannerGrab, &sequential, &openOnly, &verbose, &debug, &quiet, &noTUI,
		&scanSS, &scanSU)

	// Config-specified fields applied
	if ports != "443" {
		t.Errorf("ports: want '443', got %q", ports)
	}
	if pps != 2000 {
		t.Errorf("pps: want 2000, got %d", pps)
	}

	// Unspecified fields keep flag defaults
	if iface != "wlp0s20f3" {
		t.Errorf("iface: want default 'wlp0s20f3', got %q", iface)
	}
	if shards != 1 {
		t.Errorf("shards: want default 1, got %d", shards)
	}
	if timeout != 5*time.Second {
		t.Errorf("timeout: want default 5s, got %v", timeout)
	}
	if outputFile != "output.jsonl" {
		t.Errorf("outputFile: want default, got %q", outputFile)
	}
	if bannerGrab {
		t.Error("bannerGrab: want false (not in config)")
	}
}

func TestApplyConfig_ScanModes(t *testing.T) {
	tests := []struct {
		mode       string
		wantSS     bool
		wantSU     bool
	}{
		{"syn", true, false},
		{"udp", false, true},
		{"both", true, true},
		{"SYN", true, false},  // case insensitive
		{"UDP", false, true},
		{"Both", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg := &config.Config{
				Scan: config.ScanConfig{Mode: tt.mode},
			}
			set := map[string]bool{}

			var iface, ports, sourceIP, gwMAC, probeDir, outputFile, oG, webhookURL string
			var pps, shards, retries, arenaSlots int
			var timeout time.Duration
			var bannerGrab, sequential, openOnly, verbose, debug, quiet, noTUI bool
			scanSS := false
			scanSU := false

			applyConfig(cfg, set,
				&iface, &ports, &pps, &shards,
				&timeout, &retries, &arenaSlots,
				&sourceIP, &gwMAC, &probeDir,
				&outputFile, &oG, &webhookURL,
				&bannerGrab, &sequential, &openOnly, &verbose, &debug, &quiet, &noTUI,
				&scanSS, &scanSU)

			if scanSS != tt.wantSS {
				t.Errorf("scanSS: want %v, got %v", tt.wantSS, scanSS)
			}
			if scanSU != tt.wantSU {
				t.Errorf("scanSU: want %v, got %v", tt.wantSU, scanSU)
			}
		})
	}
}
