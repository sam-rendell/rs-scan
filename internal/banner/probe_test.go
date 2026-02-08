package banner

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDecodeYAMLBinary(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []byte
	}{
		{"ascii", "hello", []byte("hello")},
		{"cr lf", "GET / HTTP/1.0\r\n\r\n", []byte("GET / HTTP/1.0\r\n\r\n")},
		{"null and low", "\x00\x01\x02", []byte{0x00, 0x01, 0x02}},
		// Simulate what YAML produces: rune values 0x80, 0xFF, 0xA0
		// (Go source "\x80" is a raw byte, not a rune — use string(rune(...)) instead)
		{"high bytes", string([]rune{0x80, 0xFF, 0xA0}), []byte{0x80, 0xFF, 0xA0}},
	}
	for _, tt := range tests {
		got := decodeYAMLBinary(tt.in)
		if string(got) != string(tt.want) {
			t.Errorf("%s: decodeYAMLBinary = %x, want %x", tt.name, got, tt.want)
		}
	}
}

func TestDecodeYAMLBinary_HighBytes(t *testing.T) {
	// Simulate what YAML does: "\x82" in YAML double-quoted string produces
	// Unicode codepoint U+0082, which Go stores as UTF-8 bytes 0xC2 0x82.
	// decodeYAMLBinary must recover the original byte 0x82.
	yamlDecoded := string([]rune{0x30, 0x82, 0x00, 0x2f}) // as if YAML parsed "0\x82\x00/"
	got := decodeYAMLBinary(yamlDecoded)
	want := []byte{0x30, 0x82, 0x00, 0x2f}
	if string(got) != string(want) {
		t.Fatalf("high byte decode: got %x, want %x", got, want)
	}
}

func TestLoadProbes(t *testing.T) {
	// Create a temp dir with a test probe
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(`
name: test-http
protocol: tcp
ports: [80, 8080]
hello: "GET / HTTP/1.0\r\n\r\n"
recv_bytes: 1024
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "test-neg.yaml"), []byte(`
name: test-telnet
protocol: tcp
ports: [23]
recv_bytes: 512
negotiate:
  rules:
    - when: ["0xff", "0xfb", "_"]
      reply: ["0xff", "0xfe", "$1"]
  max_rounds: 5
  max_bytes: 1024
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	pt := NewProbeTable()
	if err := pt.LoadProbes(dir); err != nil {
		t.Fatal(err)
	}

	if len(pt.Probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(pt.Probes))
	}

	// Check HTTP probe
	p := pt.LookupPort(80)
	if p.Name != "test-http" {
		t.Fatalf("port 80: expected test-http, got %s", p.Name)
	}
	if string(p.Hello) != "GET / HTTP/1.0\r\n\r\n" {
		t.Fatalf("hello mismatch: %q", p.Hello)
	}
	if p.RecvMax != 1024 {
		t.Fatalf("recv_max: %d", p.RecvMax)
	}
	if p.Phase1MS != 500 {
		t.Fatalf("phase1_ms should default to 500, got %d", p.Phase1MS)
	}

	// Same probe on 8080
	p2 := pt.LookupPort(8080)
	if p2.Name != "test-http" {
		t.Fatalf("port 8080: expected test-http, got %s", p2.Name)
	}

	// Check telnet probe
	p3 := pt.LookupPort(23)
	if p3.Name != "test-telnet" {
		t.Fatalf("port 23: expected test-telnet, got %s", p3.Name)
	}
	if !p3.HasNegotiate {
		t.Fatal("telnet probe should have negotiate")
	}
	if len(p3.NegRules) != 1 {
		t.Fatalf("expected 1 neg rule, got %d", len(p3.NegRules))
	}
	if p3.NegMaxRounds != 5 {
		t.Fatalf("neg max rounds: %d", p3.NegMaxRounds)
	}

	// Unknown port → default
	pDef := pt.LookupPort(9999)
	if pDef.Name != "generic" {
		t.Fatalf("port 9999: expected generic, got %s", pDef.Name)
	}
}

func TestLoadRealProbes(t *testing.T) {
	// Load the actual probes/tcp directory
	dir := filepath.Join("..", "..", "probes", "tcp")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("probes/tcp directory not found")
	}

	pt := NewProbeTable()
	if err := pt.LoadProbes(dir); err != nil {
		t.Fatal(err)
	}

	// Should have loaded at least 55 probes
	if len(pt.Probes) < 55 {
		t.Fatalf("expected at least 55 probes, got %d", len(pt.Probes))
	}
	t.Logf("loaded %d TCP probes", len(pt.Probes))

	// Original probes
	if p := pt.LookupPort(22); p.Name != "ssh" {
		t.Errorf("port 22: got %s", p.Name)
	}
	if p := pt.LookupPort(80); p.Name != "http-get" {
		t.Errorf("port 80: got %s", p.Name)
	}
	if p := pt.LookupPort(23); p.Name != "telnet" {
		t.Errorf("port 23: got %s", p.Name)
	}
	if p := pt.LookupPort(23); !p.HasNegotiate {
		t.Error("telnet should have negotiate rules")
	}
	if p := pt.LookupPort(6379); p.Hello == nil {
		t.Error("redis should have a hello payload")
	}

	// All TCP probes — phase 1 + phase 2
	checks := []struct {
		port     uint16
		name     string
		hasHello bool
	}{
		// Phase 1
		{443, "tls", true},
		{1433, "mssql", true},
		{389, "ldap", true},
		{53, "dns", true},
		{88, "kerberos", true},
		{1883, "mqtt", true},
		{11211, "memcached", true},
		{2375, "docker", true},
		{1521, "oracle-tns", true},
		{6000, "x11", true},
		{5060, "sip", true},
		{111, "rpc", true},
		{8009, "ajp", true},
		{1723, "pptp", true},
		{1080, "socks5", true},
		// Phase 2 — active probes
		{554, "rtsp", true},
		{5672, "amqp", true},
		{2181, "zookeeper", true},
		{502, "modbus", true},
		{5222, "xmpp", true},
		{9100, "pjl", true},
		{9042, "cassandra", true},
		{50051, "grpc", true},
		{9092, "kafka", true},
		{1194, "openvpn", true},
		{11210, "couchbase", true},
		// Phase 2 — passive probes (server speaks first → no hello)
		{873, "rsync", false},
		{6667, "irc", true},
		{4222, "nats", false},
		{3690, "svn", false},
		// ICS/SCADA
		{102, "s7comm", true},
		{47808, "bacnet", true},
		{20000, "dnp3", true},
		{44818, "ethernetip", true},
		{2404, "iec104", true},
		{1911, "fox", true},
		// Additional
		{9418, "git", true},
		{4369, "epmd", true},
		{1099, "java-rmi", true},
		{5683, "coap-tcp", true},
		{179, "bgp", true},
		{515, "lpd", true},
		{3050, "firebird", true},
	}
	for _, c := range checks {
		p := pt.LookupPort(c.port)
		if p.Name != c.name {
			t.Errorf("port %d: expected %s, got %s", c.port, c.name, p.Name)
		}
		if c.hasHello && p.Hello == nil {
			t.Errorf("port %d (%s): expected hello payload", c.port, c.name)
		}
		if !c.hasHello && p.Hello != nil {
			t.Errorf("port %d (%s): expected no hello (passive probe), got %d bytes", c.port, c.name, len(p.Hello))
		}
	}
}

func TestNoPortConflicts(t *testing.T) {
	// Ensure no two probes claim the same port within TCP or UDP
	for _, subdir := range []string{"tcp", "udp"} {
		dir := filepath.Join("..", "..", "probes", subdir)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
		portOwner := make(map[uint16]string) // port → probe name
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var raw struct {
				Name  string   `yaml:"name"`
				Ports []uint16 `yaml:"ports"`
			}
			if err := yaml.Unmarshal(data, &raw); err != nil {
				t.Fatalf("%s: %v", filepath.Base(f), err)
			}
			for _, p := range raw.Ports {
				if prev, ok := portOwner[p]; ok {
					t.Errorf("[%s] port %d claimed by both %q and %q", subdir, p, prev, raw.Name)
				}
				portOwner[p] = raw.Name
			}
		}
		t.Logf("[%s] %d ports across %d probes, no conflicts", subdir, len(portOwner), len(files))
	}
}

func TestLoadRealUDPProbes(t *testing.T) {
	dir := filepath.Join("..", "..", "probes", "udp")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("probes/udp directory not found")
	}

	pt := NewProbeTable()
	if err := pt.LoadProbes(dir); err != nil {
		t.Fatal(err)
	}

	// Should have loaded at least 50 UDP probes
	if len(pt.Probes) < 50 {
		t.Fatalf("expected at least 50 UDP probes, got %d", len(pt.Probes))
	}

	// All UDP probes must have a hello payload (UDP requires sending first)
	for _, p := range pt.Probes {
		if p.Hello == nil {
			t.Errorf("UDP probe %s has no hello payload", p.Name)
		}
		if len(p.Hello) == 0 {
			t.Errorf("UDP probe %s has empty hello payload", p.Name)
		}
	}

	// Spot check key ports
	checks := []struct {
		port uint16
		name string
	}{
		{53, "dnsversionbindreq"},
		{161, "snmpv1public"},
		{123, "ntprequest"},
		{137, "nbtstat"},
		{5060, "sipoptions"},
		{1900, "upnp_msearch"},
		{3478, "stun_bind"},
	}
	for _, c := range checks {
		p := pt.LookupPort(c.port)
		if p.Name != c.name {
			t.Errorf("UDP port %d: expected %s, got %s", c.port, c.name, p.Name)
		}
	}
}

func TestTLSProbeBytes(t *testing.T) {
	// TLS ClientHello: first 5 bytes = 16 03 01 XX XX (content_type=22, version=TLS1.0, length)
	dir := filepath.Join("..", "..", "probes", "tcp")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("probes/tcp directory not found")
	}

	pt := NewProbeTable()
	if err := pt.LoadProbes(dir); err != nil {
		t.Fatal(err)
	}

	p := pt.LookupPort(443)
	if p.Name != "tls" {
		t.Fatalf("port 443: expected tls, got %s", p.Name)
	}

	if p.Hello[0] != 0x16 {
		t.Fatalf("TLS hello[0] = %02x, want 0x16 (handshake)", p.Hello[0])
	}
	if p.Hello[1] != 0x03 || p.Hello[2] != 0x01 {
		t.Fatalf("TLS version = %02x %02x, want 03 01", p.Hello[1], p.Hello[2])
	}
	// Record length from bytes 3-4
	recLen := int(p.Hello[3])<<8 | int(p.Hello[4])
	if len(p.Hello) != 5+recLen {
		t.Fatalf("TLS hello length mismatch: header says %d, actual payload %d", recLen, len(p.Hello)-5)
	}
	t.Logf("TLS probe: %d bytes", len(p.Hello))
}

func TestSNMPProbeBytes(t *testing.T) {
	// Verify that the SNMP probe hello bytes are a valid ASN.1/BER SNMP GetRequest.
	// This catches the YAML double-quote \xNN UTF-8 expansion bug: bytes >= 0x80
	// must NOT be expanded to 2-byte UTF-8.
	dir := filepath.Join("..", "..", "probes", "udp")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("probes/udp directory not found")
	}

	pt := NewProbeTable()
	if err := pt.LoadProbes(dir); err != nil {
		t.Fatal(err)
	}

	p := pt.LookupPort(161)
	if p.Name != "snmpv1public" {
		t.Fatalf("port 161: expected snmpv1public, got %s", p.Name)
	}

	hello := p.Hello

	// No 0xC2 bytes — that would indicate UTF-8 expansion of high bytes
	for i, b := range hello {
		if b == 0xC2 && i+1 < len(hello) && hello[i+1] >= 0x80 {
			t.Fatalf("UTF-8 expansion detected at offset %d: %02x %02x (YAML \\xNN bug)", i, b, hello[i+1])
		}
	}

	// First byte must be 0x30 (ASN.1 SEQUENCE)
	if hello[0] != 0x30 {
		t.Fatalf("first byte = %02x, want 0x30 (SEQUENCE)", hello[0])
	}

	// Must contain "public" community string
	found := false
	for i := 0; i+6 <= len(hello); i++ {
		if string(hello[i:i+6]) == "public" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("SNMP probe does not contain 'public' community string")
	}

	t.Logf("SNMP probe: %d bytes, hex: %x", len(hello), hello)
}

func TestNoUTF8Expansion(t *testing.T) {
	// Regression test: verify decodeYAMLBinary produces one byte per rune.
	// The old escapeString bug caused bytes >= 0x80 to become 2-byte UTF-8.
	// With the fix, len(hello) must equal the rune count of the YAML string.
	for _, subdir := range []string{"tcp", "udp"} {
		dir := filepath.Join("..", "..", "probes", subdir)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var raw struct {
				Name  string `yaml:"name"`
				Hello string `yaml:"hello"`
			}
			if err := yaml.Unmarshal(data, &raw); err != nil {
				t.Fatalf("%s: %v", filepath.Base(f), err)
			}
			if raw.Hello == "" {
				continue
			}
			decoded := decodeYAMLBinary(raw.Hello)
			runeCount := len([]rune(raw.Hello))
			if len(decoded) != runeCount {
				t.Errorf("[%s] probe %s: byte count %d != rune count %d (UTF-8 expansion bug)",
					subdir, raw.Name, len(decoded), runeCount)
			}
		}
	}
}
