package targets

import (
	"fmt"
	"net"
	"testing"
)

// TestIPAddrAddOffset verifies offset arithmetic for both IPv4-mapped and IPv6.
func TestIPAddrAddOffset(t *testing.T) {
	tests := []struct {
		name   string
		base   IPAddr
		offset uint64
		want   string
	}{
		{"IPv4 +0", IPAddrFrom4(192, 168, 1, 0), 0, "192.168.1.0"},
		{"IPv4 +1", IPAddrFrom4(192, 168, 1, 0), 1, "192.168.1.1"},
		{"IPv4 +255", IPAddrFrom4(192, 168, 1, 0), 255, "192.168.1.255"},
		{"IPv4 carry", IPAddrFrom4(192, 168, 1, 255), 1, "192.168.2.0"},
		{"IPv6 +0", FromNetIP(net.ParseIP("2001:db8::")), 0, "2001:db8::"},
		{"IPv6 +1", FromNetIP(net.ParseIP("2001:db8::")), 1, "2001:db8::1"},
		{"IPv6 +256", FromNetIP(net.ParseIP("2001:db8::")), 256, "2001:db8::100"},
		{"IPv6 +65535", FromNetIP(net.ParseIP("2001:db8::")), 65535, "2001:db8::ffff"},
		{"IPv6 carry within lo", FromNetIP(net.ParseIP("2001:db8::ffff")), 1, "2001:db8::1:0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.base.AddOffset(tt.offset)
			if s := got.String(); s != tt.want {
				t.Errorf("AddOffset(%d) = %s, want %s", tt.offset, s, tt.want)
			}
		})
	}
}

// TestParseCIDRRange_IPv6 verifies IPv6 CIDR parsing.
func TestParseCIDRRange_IPv6(t *testing.T) {
	tests := []struct {
		cidr      string
		wantBase  string
		wantCount uint64
		wantErr   bool
	}{
		{"2001:db8::/112", "2001:db8::", 65536, false},
		{"2001:db8::/120", "2001:db8::", 256, false},
		{"2001:db8::/128", "2001:db8::", 1, false},
		{"2001:db8::/127", "2001:db8::", 2, false},
		{"2001:db8::/32", "", 0, true}, // too large (< /64)
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			base, count, err := parseCIDRRange(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCIDRRange(%q) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if s := base.String(); s != tt.wantBase {
				t.Errorf("base = %s, want %s", s, tt.wantBase)
			}
			if count != tt.wantCount {
				t.Errorf("count = %d, want %d", count, tt.wantCount)
			}
		})
	}
}

// TestParseCIDRRange_IPv4 verifies IPv4 CIDR still works.
func TestParseCIDRRange_IPv4(t *testing.T) {
	base, count, err := parseCIDRRange("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if s := base.String(); s != "192.168.1.0" {
		t.Errorf("base = %s, want 192.168.1.0", s)
	}
	if count != 256 {
		t.Errorf("count = %d, want 256", count)
	}
}

// TestTupleIterator_IPv6Single verifies single IPv6 target scanning.
func TestTupleIterator_IPv6Single(t *testing.T) {
	iter, err := NewTupleIterator([]string{"2001:db8::1"}, "80,443", nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if iter.TotalIPs() != 1 {
		t.Fatalf("TotalIPs = %d, want 1", iter.TotalIPs())
	}
	if iter.TotalPorts() != 2 {
		t.Fatalf("TotalPorts = %d, want 2", iter.TotalPorts())
	}

	seen := make(map[string]bool)
	for {
		ip, port, ok := iter.Next()
		if !ok {
			break
		}
		key := fmt.Sprintf("%s:%d", ip.String(), port)
		seen[key] = true
	}

	if !seen["2001:db8::1:80"] {
		t.Error("missing 2001:db8::1:80")
	}
	if !seen["2001:db8::1:443"] {
		t.Error("missing 2001:db8::1:443")
	}
	if len(seen) != 2 {
		t.Errorf("expected 2 tuples, got %d: %v", len(seen), seen)
	}
}

// TestTupleIterator_IPv6CIDR verifies IPv6 CIDR target iteration.
func TestTupleIterator_IPv6CIDR(t *testing.T) {
	// /126 = 4 IPs
	iter, err := NewTupleIterator([]string{"2001:db8::/126"}, "80", nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if iter.TotalIPs() != 4 {
		t.Fatalf("TotalIPs = %d, want 4", iter.TotalIPs())
	}

	expected := []string{
		"2001:db8::",
		"2001:db8::1",
		"2001:db8::2",
		"2001:db8::3",
	}

	for _, exp := range expected {
		ip, port, ok := iter.Next()
		if !ok {
			t.Fatalf("exhausted before %s", exp)
		}
		if s := ip.String(); s != exp {
			t.Errorf("got %s, want %s", s, exp)
		}
		if port != 80 {
			t.Errorf("port = %d, want 80", port)
		}
	}

	if _, _, ok := iter.Next(); ok {
		t.Error("should be exhausted")
	}
}

// TestTupleIterator_MixedV4V6 verifies mixed IPv4 + IPv6 targets.
func TestTupleIterator_MixedV4V6(t *testing.T) {
	iter, err := NewTupleIterator([]string{"10.0.0.1", "2001:db8::1"}, "22", nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if iter.TotalIPs() != 2 {
		t.Fatalf("TotalIPs = %d, want 2", iter.TotalIPs())
	}

	ip1, _, ok := iter.Next()
	if !ok {
		t.Fatal("exhausted")
	}
	if !ip1.IsIPv4() {
		t.Errorf("first IP should be IPv4, got %s", ip1.String())
	}
	if s := ip1.String(); s != "10.0.0.1" {
		t.Errorf("first IP = %s, want 10.0.0.1", s)
	}

	ip2, _, ok := iter.Next()
	if !ok {
		t.Fatal("exhausted")
	}
	if ip2.IsIPv4() {
		t.Errorf("second IP should be IPv6, got %s", ip2.String())
	}
	if s := ip2.String(); s != "2001:db8::1" {
		t.Errorf("second IP = %s, want 2001:db8::1", s)
	}

	if _, _, ok := iter.Next(); ok {
		t.Error("should be exhausted")
	}
}

// TestTupleIterator_IPv6Randomized verifies Feistel permutation works with IPv6.
func TestTupleIterator_IPv6Randomized(t *testing.T) {
	iter, err := NewTupleIterator([]string{"2001:db8::/120"}, "80", nil) // randomized
	if err != nil {
		t.Fatal(err)
	}

	// /120 = 256 IPs * 1 port = 256 tuples
	if iter.TotalIPs() != 256 {
		t.Fatalf("TotalIPs = %d, want 256", iter.TotalIPs())
	}

	seen := make(map[string]bool)
	for {
		ip, _, ok := iter.Next()
		if !ok {
			break
		}
		seen[ip.String()] = true
	}

	if len(seen) != 256 {
		t.Errorf("expected 256 unique IPs, got %d", len(seen))
	}
}
