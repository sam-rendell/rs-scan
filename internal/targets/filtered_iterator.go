package targets

// FilteredIterator wraps an Iterator and applies an exclusion list.
type FilteredIterator struct {
	source    Iterator
	exclusion *IntervalTree
}

// NewFilteredIterator creates a wrapper that skips excluded IPs.
func NewFilteredIterator(source Iterator, exclusion *IntervalTree) *FilteredIterator {
	return &FilteredIterator{
		source:    source,
		exclusion: exclusion,
	}
}

// Seek advances the iterator to the specified IP.
func (it *FilteredIterator) Seek(ip IPAddr) {
	it.source.Seek(ip)
}

func (it *FilteredIterator) GetState() uint64 {
	return it.source.GetState()
}

// Next returns the next valid IP, skipping excluded ranges.
func (it *FilteredIterator) Next() (IPAddr, bool) {
	for {
		ip, ok := it.source.Next()
		if !ok {
			return IPAddr{}, false
		}

		// IntervalTree still uses uint32 (Phase 1 compat shim)
		ipU32 := IPAddrToUint32(ip)
		blocked, endOfBlock := it.exclusion.Contains(ipU32)
		if !blocked {
			return ip, true
		}

		// If blocked, skip to the end of the block + 1.
		it.source.Seek(IPToIPAddr(endOfBlock + 1))
	}
}

func (it *FilteredIterator) Split(n int) []Iterator {
	sources := it.source.Split(n)
	wrappers := make([]Iterator, len(sources))
	for i, s := range sources {
		wrappers[i] = NewFilteredIterator(s, it.exclusion)
	}
	return wrappers
}
