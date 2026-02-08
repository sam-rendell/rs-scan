package targets

import (
	"reflect"
	"testing"
)

func TestParsePortSpec_TCPPrefix(t *testing.T) {
	tcp, udp, err := ParsePortSpec("T:22,80,443", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tcp, []uint16{22, 80, 443}) {
		t.Fatalf("tcp = %v, want [22 80 443]", tcp)
	}
	if udp != nil {
		t.Fatalf("udp = %v, want nil", udp)
	}
}

func TestParsePortSpec_UDPPrefix(t *testing.T) {
	tcp, udp, err := ParsePortSpec("U:53,161,5353", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if tcp != nil {
		t.Fatalf("tcp = %v, want nil", tcp)
	}
	if !reflect.DeepEqual(udp, []uint16{53, 161, 5353}) {
		t.Fatalf("udp = %v, want [53 161 5353]", udp)
	}
}

func TestParsePortSpec_Mixed(t *testing.T) {
	tcp, udp, err := ParsePortSpec("T:22,80,U:53,161", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tcp, []uint16{22, 80}) {
		t.Fatalf("tcp = %v, want [22 80]", tcp)
	}
	if !reflect.DeepEqual(udp, []uint16{53, 161}) {
		t.Fatalf("udp = %v, want [53 161]", udp)
	}
}

func TestParsePortSpec_BareDefaultTCP(t *testing.T) {
	tcp, udp, err := ParsePortSpec("80,443", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tcp, []uint16{80, 443}) {
		t.Fatalf("tcp = %v, want [80 443]", tcp)
	}
	if udp != nil {
		t.Fatalf("udp = %v, want nil", udp)
	}
}

func TestParsePortSpec_BareDefaultUDP(t *testing.T) {
	tcp, udp, err := ParsePortSpec("53,161", "udp")
	if err != nil {
		t.Fatal(err)
	}
	if tcp != nil {
		t.Fatalf("tcp = %v, want nil", tcp)
	}
	if !reflect.DeepEqual(udp, []uint16{53, 161}) {
		t.Fatalf("udp = %v, want [53 161]", udp)
	}
}

func TestParsePortSpec_BareDefaultBoth(t *testing.T) {
	tcp, udp, err := ParsePortSpec("80,443", "both")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tcp, []uint16{80, 443}) {
		t.Fatalf("tcp = %v, want [80 443]", tcp)
	}
	if !reflect.DeepEqual(udp, []uint16{80, 443}) {
		t.Fatalf("udp = %v, want [80 443]", udp)
	}
}

func TestParsePortSpec_Range(t *testing.T) {
	tcp, _, err := ParsePortSpec("T:20-25", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	expected := []uint16{20, 21, 22, 23, 24, 25}
	if !reflect.DeepEqual(tcp, expected) {
		t.Fatalf("tcp = %v, want %v", tcp, expected)
	}
}

func TestParsePortSpec_MixedWithRange(t *testing.T) {
	tcp, udp, err := ParsePortSpec("T:1-3,U:53", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tcp, []uint16{1, 2, 3}) {
		t.Fatalf("tcp = %v, want [1 2 3]", tcp)
	}
	if !reflect.DeepEqual(udp, []uint16{53}) {
		t.Fatalf("udp = %v, want [53]", udp)
	}
}

func TestParsePortSpec_CaseInsensitive(t *testing.T) {
	tcp, udp, err := ParsePortSpec("t:22,u:53", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tcp, []uint16{22}) {
		t.Fatalf("tcp = %v, want [22]", tcp)
	}
	if !reflect.DeepEqual(udp, []uint16{53}) {
		t.Fatalf("udp = %v, want [53]", udp)
	}
}

func TestParsePortSpec_InvalidPort(t *testing.T) {
	_, _, err := ParsePortSpec("T:abc", "tcp")
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}
