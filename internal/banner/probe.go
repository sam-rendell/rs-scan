package banner

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// CompiledProbe is the runtime representation of a service probe.
// Loaded once at startup, referenced by index from connection state.
type CompiledProbe struct {
	Name     string
	Hello    []byte // pre-escaped payload to send after phase1 timeout (nil = passive only)
	RecvMax  uint16 // max bytes to capture
	Phase1MS uint16 // ms to wait before sending hello (0 = no hello / passive only)

	// Negotiate rules (for protocols like Telnet that need IAC handling)
	HasNegotiate bool
	NegRules     []NegRule
	NegMaxRounds uint8
	NegMaxBytes  uint16
	EscapeOn     []byte // abort negotiate if any of these bytes seen
}

// NegRule is a single byte-pattern match/reply rule for the negotiate step.
// When contains a 0xFF wildcard marker position, and Reply can reference $1 for the captured byte.
type NegRule struct {
	When       []byte // byte pattern to match (WildcardByte = match any single byte)
	Reply      []byte // bytes to send (BackrefByte at position i = insert captured byte i)
	WildcardAt int    // index of the wildcard in When (-1 if none)
}

// WildcardByte is used internally to mark a wildcard position in NegRule.When.
const WildcardByte = byte(0xFE) // internal sentinel, not a real protocol byte

// probeYAML is the on-disk YAML structure for a probe definition.
type probeYAML struct {
	Name      string   `yaml:"name"`
	Protocol  string   `yaml:"protocol"`
	Ports     []uint16 `yaml:"ports"`
	Hello     string   `yaml:"hello,omitempty"`
	RecvBytes uint16   `yaml:"recv_bytes,omitempty"`
	Phase1MS  uint16   `yaml:"phase1_ms,omitempty"`
	Transport string   `yaml:"transport,omitempty"`
	Negotiate *negYAML `yaml:"negotiate,omitempty"`
}

type negYAML struct {
	Rules     []negRuleYAML `yaml:"rules"`
	MaxRounds uint8         `yaml:"max_rounds,omitempty"`
	MaxBytes  uint16        `yaml:"max_bytes,omitempty"`
	EscapeOn  []string      `yaml:"escape_on,omitempty"`
}

type negRuleYAML struct {
	When  []string `yaml:"when"`
	Reply []string `yaml:"reply"`
}

// ProbeTable holds all compiled probes and the port→probe lookup array.
type ProbeTable struct {
	Probes   []*CompiledProbe
	ByPort   [65536]*CompiledProbe // port index, nil = generic passive grab
	ByName   map[string]*CompiledProbe
	Default  *CompiledProbe // fallback for ports with no specific probe
}

// NewProbeTable creates an empty table with a default passive probe.
func NewProbeTable() *ProbeTable {
	def := &CompiledProbe{
		Name:     "generic",
		RecvMax:  512,
		Phase1MS: 0, // passive only — no hello
	}
	return &ProbeTable{
		ByName:  make(map[string]*CompiledProbe),
		Default: def,
	}
}

// LoadProbes reads all YAML files from the given directory and populates the table.
func (pt *ProbeTable) LoadProbes(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("glob probes: %w", err)
	}

	for _, f := range files {
		if err := pt.loadFile(f); err != nil {
			return fmt.Errorf("load %s: %w", filepath.Base(f), err)
		}
	}

	return nil
}

func (pt *ProbeTable) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var raw probeYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}

	probe := &CompiledProbe{
		Name:     raw.Name,
		RecvMax:  raw.RecvBytes,
		Phase1MS: raw.Phase1MS,
	}

	if probe.RecvMax == 0 {
		probe.RecvMax = 512 // default
	}

	// Default phase1 for probes with a hello payload
	if raw.Hello != "" {
		probe.Hello = decodeYAMLBinary(raw.Hello)
		if probe.Phase1MS == 0 {
			probe.Phase1MS = 500 // default 500ms passive wait before sending
		}
	}

	// Compile negotiate rules
	if raw.Negotiate != nil {
		probe.HasNegotiate = true
		probe.NegMaxRounds = raw.Negotiate.MaxRounds
		if probe.NegMaxRounds == 0 {
			probe.NegMaxRounds = 10
		}
		probe.NegMaxBytes = raw.Negotiate.MaxBytes
		if probe.NegMaxBytes == 0 {
			probe.NegMaxBytes = 2048
		}
		for _, esc := range raw.Negotiate.EscapeOn {
			probe.EscapeOn = append(probe.EscapeOn, parseByteValues(esc)...)
		}
		for _, rule := range raw.Negotiate.Rules {
			nr, err := compileNegRule(rule)
			if err != nil {
				return fmt.Errorf("negotiate rule: %w", err)
			}
			probe.NegRules = append(probe.NegRules, nr)
		}
	}

	// Register
	pt.Probes = append(pt.Probes, probe)
	pt.ByName[probe.Name] = probe
	probeID := uint8(len(pt.Probes) - 1)
	_ = probeID // stored implicitly as index

	for _, port := range raw.Ports {
		pt.ByPort[port] = probe
	}

	return nil
}

// LookupPort returns the probe for a port, or the default passive probe.
func (pt *ProbeTable) LookupPort(port uint16) *CompiledProbe {
	if p := pt.ByPort[port]; p != nil {
		return p
	}
	return pt.Default
}

// ProbeID returns the index of a probe in the Probes slice, or 0 for default.
func (pt *ProbeTable) ProbeID(p *CompiledProbe) uint8 {
	for i, pp := range pt.Probes {
		if pp == p {
			return uint8(i)
		}
	}
	return 0
}

// decodeYAMLBinary converts a YAML-decoded string back to raw bytes.
// YAML double-quoted \xNN escapes produce Unicode codepoint U+00NN, which Go
// stores as multi-byte UTF-8 for values >= 0x80. This function reverses that
// by extracting each rune's value as a single byte.
func decodeYAMLBinary(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		out = append(out, byte(r))
	}
	return out
}

// compileNegRule converts a YAML negotiate rule into a compiled NegRule.
func compileNegRule(raw negRuleYAML) (NegRule, error) {
	nr := NegRule{WildcardAt: -1}

	for i, v := range raw.When {
		if v == "_" {
			nr.When = append(nr.When, WildcardByte)
			nr.WildcardAt = i
		} else {
			b := parseByteValues(v)
			nr.When = append(nr.When, b...)
		}
	}

	for _, v := range raw.Reply {
		if strings.HasPrefix(v, "$") {
			// Backref — for now we only support $1 which means "insert captured wildcard byte"
			nr.Reply = append(nr.Reply, WildcardByte) // placeholder replaced at runtime
		} else {
			b := parseByteValues(v)
			nr.Reply = append(nr.Reply, b...)
		}
	}

	return nr, nil
}

// parseByteValues parses a hex string like "0xff" into a byte.
func parseByteValues(s string) []byte {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 8)
		if err == nil {
			return []byte{byte(v)}
		}
	}
	// Try decimal
	v, err := strconv.ParseUint(s, 10, 8)
	if err == nil {
		return []byte{byte(v)}
	}
	// Fallback: treat as literal bytes
	return []byte(s)
}
