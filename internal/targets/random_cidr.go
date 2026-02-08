package targets

// RandomCIDRIterator iterates over a CIDR block in pseudo-random order.
type RandomCIDRIterator struct {
	baseIP uint32
	count  uint64
	max    uint64
	perm   *FeistelPermutation
}

// NewRandomCIDRIterator creates a shuffled iterator.
func NewRandomCIDRIterator(cidrStr string) (*RandomCIDRIterator, error) {
	iter, err := NewCIDRIterator(cidrStr)
	if err != nil {
		return nil, err
	}

	size := uint64(iter.last) - uint64(iter.current) + 1
	perm := NewFeistelPermutation(size)

	return &RandomCIDRIterator{
		baseIP: iter.current,
		count:  0,
		max:    size,
		perm:   perm,
	}, nil
}

func (it *RandomCIDRIterator) Next() (uint32, bool) {
	if it.count >= it.max {
		return 0, false
	}

	idx := it.count
	it.count++

	offset := it.perm.Permute(idx)

	return it.baseIP + uint32(offset), true
}

func (it *RandomCIDRIterator) GetState() uint64 {
	return it.count
}

func (it *RandomCIDRIterator) SetState(val uint64) {
	it.count = val
}

func (it *RandomCIDRIterator) Seek(target uint32) {
	// Seeking in a permuted stream requires decryption or linear scan.
	// For checkpoint resume, treat target as the count index.
}

func (it *RandomCIDRIterator) Split(n int) []Iterator {
	perShard := it.max / uint64(n)
	var shards []Iterator

	start := uint64(0)
	for i := 0; i < n; i++ {
		end := start + perShard
		if i == n-1 {
			end = it.max
		}

		shards = append(shards, &RandomCIDRIterator{
			baseIP: it.baseIP,
			count:  start,
			max:    end,
			perm:   it.perm,
		})
		start = end
	}
	return shards
}
