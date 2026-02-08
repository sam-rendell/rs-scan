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
func (it *FilteredIterator) Seek(ip uint32) {
	it.source.Seek(ip)
}

func (it *FilteredIterator) GetState() uint64 {
	return it.source.GetState()
}

func (it *FilteredIterator) SetState(val uint64) {
	it.source.SetState(val)
}

// Next returns the next valid IP, skipping excluded ranges.
func (it *FilteredIterator) Next() (uint32, bool) {
	for {
		ip, ok := it.source.Next()
		if !ok {
			return 0, false
		}

		blocked, endOfBlock := it.exclusion.Contains(ip)
		if !blocked {
			return ip, true
		}

		// If blocked, skip to the end of the block + 1.
		it.source.Seek(endOfBlock + 1)
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
