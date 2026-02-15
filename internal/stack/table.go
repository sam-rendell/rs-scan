package stack

import (
	"sync"
	"sync/atomic"
	"time"
)

// statePool reuses State structs to avoid heap allocation per SYN.
var statePool = sync.Pool{
	New: func() any { return &State{} },
}

func allocState() *State {
	s := statePool.Get().(*State)
	*s = State{ArenaSlot: NoArenaSlot}
	return s
}

// ReleaseExpired returns expired State structs to the pool for reuse.
// Must be called after the caller is done processing the expired slice.
func ReleaseExpired(expired []*State) {
	for _, s := range expired {
		s.Banner = nil // release any held memory
		statePool.Put(s)
	}
}

// sharedNow is a coarse timestamp updated by a background goroutine.
// Avoids calling time.Now() on every packet in the hot path.
var sharedNow int64

func init() {
	atomic.StoreInt64(&sharedNow, time.Now().UnixNano())
	go func() {
		for {
			time.Sleep(1 * time.Millisecond)
			atomic.StoreInt64(&sharedNow, time.Now().UnixNano())
		}
	}()
}

// NowNano returns a coarse nanosecond timestamp (1ms resolution).
// Use this instead of time.Now().UnixNano() in hot paths.
func NowNano() int64 {
	return atomic.LoadInt64(&sharedNow)
}

// IPAddr is a 16-byte fixed-size IP address (matches targets.IPAddr layout).
// Duplicated here to avoid import cycle between stack and targets.
type IPAddr [16]byte

// State represents the status of a tracked connection.
type State struct {
	SrcIP   IPAddr
	DstIP   IPAddr
	SrcPort uint16
	DstPort uint16
	Status  ConnectionStatus

	// TCP State for Negotiation
	Seq uint32
	Ack uint32

	Updated int64 // UnixNano

	// Banner Data (legacy field, used when banner engine is not active)
	Banner []byte

	// Banner Grab Engine State
	ArenaSlot      uint32 // index into BannerArena (0xFFFFFFFF = no slot)
	RecvLen        uint16 // bytes accumulated in arena slot
	RecvMax        uint16 // max bytes to capture (from probe definition)
	ProbeID        uint8  // index into compiled probe table
	Step           uint8  // 0=wait_for_data, 1=hello_sent, 2=negotiating, 3=receiving
	NegRound       uint8  // negotiate iteration counter
	ConnDeadline   int64  // absolute nanosecond timestamp: hard kill
	Phase1Deadline int64  // absolute nanosecond timestamp: send hello if silence
}

type ConnectionStatus int

const (
	StatusSynSent ConnectionStatus = iota
	StatusEstablished
	StatusClosed
)

// Banner grab step constants.
const (
	StepWaitForData uint8 = 0
	StepHelloSent   uint8 = 1
	StepNegotiating uint8 = 2
	StepReceiving   uint8 = 3
)

// NoArenaSlot is the sentinel value for State.ArenaSlot when no arena slot is assigned.
const NoArenaSlot = uint32(0xFFFFFFFF)

const shardCount = 256

// ConnectionTable is a sharded thread-safe map.
type ConnectionTable struct {
	shards [shardCount]*shard
}

type shard struct {
	sync.RWMutex
	items map[uint64]*State
}

// NewConnectionTable creates a new table.
func NewConnectionTable() *ConnectionTable {
	t := &ConnectionTable{}
	for i := 0; i < shardCount; i++ {
		t.shards[i] = &shard{
			items: make(map[uint64]*State),
		}
	}
	return t
}

func hash4Tuple(srcIP, dstIP IPAddr, srcPort, dstPort uint16) uint64 {
	// FNV-1a over 36 bytes (16+16+2+2) — no allocations, good avalanche.
	const (
		offset = uint64(14695981039346656037)
		prime  = uint64(1099511628211)
	)
	h := offset
	// Hash all 16 bytes of srcIP
	for i := 0; i < 16; i += 2 {
		h ^= uint64(srcIP[i])<<8 | uint64(srcIP[i+1])
		h *= prime
	}
	// Hash all 16 bytes of dstIP
	for i := 0; i < 16; i += 2 {
		h ^= uint64(dstIP[i])<<8 | uint64(dstIP[i+1])
		h *= prime
	}
	h ^= uint64(srcPort) | (uint64(dstPort) << 16)
	h *= prime
	return h
}

func (t *ConnectionTable) AddSynSent(srcIP, dstIP IPAddr, srcPort, dstPort uint16, seq uint32) {
	key := hash4Tuple(srcIP, dstIP, srcPort, dstPort)
	sh := t.shards[key%shardCount]

	s := allocState()
	s.SrcIP = srcIP
	s.DstIP = dstIP
	s.SrcPort = srcPort
	s.DstPort = dstPort
	s.Status = StatusSynSent
	s.Seq = seq
	s.Updated = NowNano()

	sh.Lock()
	if old, ok := sh.items[key]; ok {
		statePool.Put(old) // recycle displaced entry
	}
	sh.items[key] = s
	sh.Unlock()
}

func (t *ConnectionTable) Get(srcIP, dstIP IPAddr, srcPort, dstPort uint16) (*State, bool) {
	key := hash4Tuple(srcIP, dstIP, srcPort, dstPort)
	shard := t.shards[key%shardCount]

	shard.RLock()
	val, ok := shard.items[key]
	shard.RUnlock()
	return val, ok
}

func (t *ConnectionTable) UpdateState(srcIP, dstIP IPAddr, srcPort, dstPort uint16, status ConnectionStatus, seq, ack uint32, data []byte) {
	key := hash4Tuple(srcIP, dstIP, srcPort, dstPort)
	shard := t.shards[key%shardCount]

	shard.Lock()
	if val, ok := shard.items[key]; ok {
		val.Status = status
		val.Updated = NowNano()
		if seq != 0 { val.Seq = seq }
		if ack != 0 { val.Ack = ack }
		if len(data) > 0 {
			val.Banner = append(val.Banner, data...)
		}
	}
	shard.Unlock()
}

// Cleanup removes entries that are either inactive (Updated older than timeout)
// or have exceeded their hard ConnDeadline (active but running too long).
// Uses two-pass approach: read lock to find expired keys, write lock to delete.
// This minimizes write-lock hold time so the receiver isn't blocked.
func (t *ConnectionTable) Cleanup(timeout time.Duration) []*State {
	var expired []*State
	nowNS := NowNano()
	threshold := nowNS - timeout.Nanoseconds()

	for i := 0; i < shardCount; i++ {
		s := t.shards[i]

		// Pass 1: collect expired keys under read lock
		var toDelete []uint64
		s.RLock()
		for k, v := range s.items {
			if v.Updated < threshold || (v.ConnDeadline != 0 && v.ConnDeadline <= nowNS) {
				toDelete = append(toDelete, k)
			}
		}
		s.RUnlock()

		if len(toDelete) == 0 {
			continue
		}

		// Pass 2: delete under write lock (re-check to avoid races)
		s.Lock()
		for _, k := range toDelete {
			if v, ok := s.items[k]; ok {
				if v.Updated < threshold || (v.ConnDeadline != 0 && v.ConnDeadline <= nowNS) {
					expired = append(expired, v)
					delete(s.items, k)
				}
			}
		}
		s.Unlock()
	}
	return expired
}

// SweepRetransmit iterates all shards and calls fn for SynSent connections
// in the given source port range that have fewer retries than maxRetries.
// Used for UDP retransmission: fn should resend the probe packet.
// NegRound is reused as the retry counter for UDP entries.
func (t *ConnectionTable) SweepRetransmit(minSrcPort, maxSrcPort uint16, maxRetries uint8, fn func(st *State)) {
	for i := 0; i < shardCount; i++ {
		s := t.shards[i]
		s.Lock()
		for _, v := range s.items {
			if v.Status == StatusSynSent &&
				v.SrcPort >= minSrcPort && v.SrcPort <= maxSrcPort &&
				v.NegRound < maxRetries {
				v.NegRound++
				fn(v)
			}
		}
		s.Unlock()
	}
}

// SweepPhase1 iterates all shards and calls fn for connections where
// Phase1Deadline is set and has been reached. This fires hello payloads
// for connections that haven't received any data after the passive wait period.
func (t *ConnectionTable) SweepPhase1(nowNS int64, fn func(st *State)) {
	for i := 0; i < shardCount; i++ {
		s := t.shards[i]
		s.Lock()
		for _, v := range s.items {
			if v.Phase1Deadline != 0 && v.Phase1Deadline <= nowNS && v.Step == StepWaitForData {
				fn(v)
			}
		}
		s.Unlock()
	}
}
