package targets

import (
	"net"
	"testing"
)

func TestCIDRIterator(t *testing.T) {
	// 192.168.1.0/30 -> .0, .1, .2, .3 (4 IPs)
	iter, err := NewCIDRIterator("192.168.1.0/30")
	if err != nil {
		t.Fatalf("Failed to create iterator: %v", err)
	}

	expected := []string{
		"192.168.1.0",
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
	}

	for _, exp := range expected {
		ip, ok := iter.Next()
		if !ok {
			t.Fatal("Iterator exhausted prematurely")
		}
		if ipStr := ip.String(); ipStr != exp {
			t.Errorf("Expected %s, got %s", exp, ipStr)
		}
	}

	if _, ok := iter.Next(); ok {
		t.Error("Iterator should be exhausted")
	}
}

func TestRangeIterator(t *testing.T) {
	// 10.0.1-2.1-2 -> 
	// 10.0.1.1, 10.0.1.2
	// 10.0.2.1, 10.0.2.2
	iter, err := NewRangeIterator("10.0.1-2.1-2")
	if err != nil {
		t.Fatalf("Failed to create iterator: %v", err)
	}

	expected := []string{
		"10.0.1.1",
		"10.0.1.2",
		"10.0.2.1",
		"10.0.2.2",
	}

	for _, exp := range expected {
		ip, ok := iter.Next()
		if !ok {
			t.Fatal("Iterator exhausted prematurely")
		}
		if ipStr := ip.String(); ipStr != exp {
			t.Errorf("Expected %s, got %s", exp, ipStr)
		}
	}

	if _, ok := iter.Next(); ok {
		t.Error("Iterator should be exhausted")
	}
}

func TestCIDRSplit(t *testing.T) {
	// 192.168.1.0/24 -> 256 IPs. Split into 4 -> 64 IPs each.
	iter, _ := NewCIDRIterator("192.168.1.0/24")
	shards := iter.Split(4)

	if len(shards) != 4 {
		t.Fatalf("Expected 4 shards, got %d", len(shards))
	}

	count := 0
	for _, shard := range shards {
		for {
			_, ok := shard.Next()
			if !ok {
				break
			}
			count++
		}
	}

	if count != 256 {
		t.Errorf("Split iterators yielded %d IPs, expected 256", count)
	}
}

func TestExclusion(t *testing.T) {
	// Range: 192.168.1.0/24 (256 IPs)
	// Exclude: 192.168.1.10 - 192.168.1.200
	iter, _ := NewCIDRIterator("192.168.1.0/24")

	tree := &IntervalTree{}
	// Exclude .10 to .200
	startEx := IPToUint32(net.ParseIP("192.168.1.10"))
	endEx := IPToUint32(net.ParseIP("192.168.1.200"))
	tree.Insert(startEx, endEx)

	filtered := NewFilteredIterator(iter, tree)

	count := 0
	for {
		ip, ok := filtered.Next()
		if !ok {
			break
		}
		ipU32 := IPAddrToUint32(ip)
		if ipU32 >= startEx && ipU32 <= endEx {
			t.Errorf("Excluded IP found: %s", ip.String())
		}
		count++
	}

	// Expected: 256 - (200 - 10 + 1) = 256 - 191 = 65
	if count != 65 {
		t.Errorf("Expected 65 IPs, got %d", count)
	}
}
