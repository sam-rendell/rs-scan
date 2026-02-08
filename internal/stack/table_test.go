package stack

import (
	"testing"
	"time"
)

func TestConnectionTable(t *testing.T) {
	table := NewConnectionTable()

	srcIP := uint32(1)
	dstIP := uint32(2)
	srcPort := uint16(100)
	dstPort := uint16(80)

	// 1. Add
	table.AddSynSent(srcIP, dstIP, srcPort, dstPort, 12345)

	// 2. Get
	state, ok := table.Get(srcIP, dstIP, srcPort, dstPort)
	if !ok {
		t.Fatal("Expected to find connection")
	}
	if state.Status != StatusSynSent {
		t.Errorf("Expected status SynSent, got %v", state.Status)
	}
	if state.Seq != 12345 {
		t.Errorf("Expected seq 12345, got %v", state.Seq)
	}

	// 3. Update
	table.UpdateState(srcIP, dstIP, srcPort, dstPort, StatusEstablished, 100, 200, nil)
	state, _ = table.Get(srcIP, dstIP, srcPort, dstPort)
	if state.Status != StatusEstablished {
		t.Errorf("Expected status Established, got %v", state.Status)
	}
}

func TestConnectionTableNoCollision(t *testing.T) {
	table := NewConnectionTable()

	// Insert two entries that would collide under the old XOR hash
	table.AddSynSent(1, 2, 100, 80, 111)
	table.AddSynSent(2, 1, 100, 80, 222)

	s1, ok1 := table.Get(1, 2, 100, 80)
	s2, ok2 := table.Get(2, 1, 100, 80)

	if !ok1 || !ok2 {
		t.Fatal("Expected both entries to exist")
	}
	if s1.Seq != 111 || s2.Seq != 222 {
		t.Errorf("Hash collision: entries overwrote each other (seq1=%d, seq2=%d)", s1.Seq, s2.Seq)
	}
}

func TestCleanup(t *testing.T) {
	table := NewConnectionTable()
	table.AddSynSent(1, 2, 100, 80, 0)

	// Should not expire yet
	expired := table.Cleanup(5 * time.Second)
	if len(expired) != 0 {
		t.Errorf("Expected 0 expired, got %d", len(expired))
	}

	// Should still be there
	_, ok := table.Get(1, 2, 100, 80)
	if !ok {
		t.Fatal("Entry should still exist")
	}
}

func TestAddSynSent_ArenaSlotSentinel(t *testing.T) {
	table := NewConnectionTable()

	// Create 100 SynSent entries (no banner grab)
	for i := uint32(0); i < 100; i++ {
		table.AddSynSent(1, i+10, uint16(1024+i), 80, i)
	}

	// Every SynSent entry must have ArenaSlot = NoArenaSlot.
	// If ArenaSlot is 0 (zero-value bug), CheckTimers would
	// try to free arena slot 0 for every expired entry, blocking
	// the management goroutine.
	for i := uint32(0); i < 100; i++ {
		st, ok := table.Get(1, i+10, uint16(1024+i), 80)
		if !ok {
			t.Fatalf("entry %d not found", i)
		}
		if st.ArenaSlot != NoArenaSlot {
			t.Fatalf("entry %d: ArenaSlot = %d, want NoArenaSlot (%d). "+
				"This causes CheckTimers to arena.Free bogus slots, deadlocking the management loop.",
				i, st.ArenaSlot, NoArenaSlot)
		}
	}
}

func TestCleanupExpiredNoArenaSlot(t *testing.T) {
	table := NewConnectionTable()

	// Create entries and expire them immediately
	for i := uint32(0); i < 50; i++ {
		table.AddSynSent(1, i+10, uint16(1024+i), 80, i)
	}

	// Let the coarse clock (1ms resolution) advance past the Updated timestamps
	time.Sleep(2 * time.Millisecond)

	// Expire everything (timeout=0)
	expired := table.Cleanup(0)
	if len(expired) != 50 {
		t.Fatalf("expected 50 expired, got %d", len(expired))
	}

	// All expired SynSent entries must have ArenaSlot = NoArenaSlot
	for _, st := range expired {
		if st.ArenaSlot != NoArenaSlot {
			t.Fatalf("expired entry has ArenaSlot=%d, want NoArenaSlot. "+
				"This would cause arena.Free to block.", st.ArenaSlot)
		}
	}
	ReleaseExpired(expired)
}

// TestCleanupConnDeadline verifies that Cleanup expires active connections
// that have exceeded their hard ConnDeadline, even if they were recently updated.
// Without this, a target streaming data continuously would never be reaped.
func TestCleanupConnDeadline(t *testing.T) {
	table := NewConnectionTable()

	// Add an entry and set a ConnDeadline in the past
	table.AddSynSent(1, 2, 100, 80, 0)
	st, ok := table.Get(1, 2, 100, 80)
	if !ok {
		t.Fatal("entry not found")
	}
	// Simulate: connection was recently active (Updated=now) but deadline passed
	now := NowNano()
	st.Updated = now           // fresh activity — would survive inactivity check
	st.ConnDeadline = now - 1  // deadline already passed

	// Use a long timeout so inactivity alone wouldn't expire it
	expired := table.Cleanup(10 * time.Second)
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired (ConnDeadline), got %d", len(expired))
	}

	// Verify entry was removed from table
	_, ok = table.Get(1, 2, 100, 80)
	if ok {
		t.Fatal("entry should have been removed by ConnDeadline")
	}
	ReleaseExpired(expired)
}

// TestCleanupConnDeadlineNotExpiredEarly verifies that a connection with a
// future ConnDeadline is NOT expired prematurely.
func TestCleanupConnDeadlineNotExpiredEarly(t *testing.T) {
	table := NewConnectionTable()

	table.AddSynSent(1, 2, 100, 80, 0)
	st, ok := table.Get(1, 2, 100, 80)
	if !ok {
		t.Fatal("entry not found")
	}
	now := NowNano()
	st.Updated = now
	st.ConnDeadline = now + int64(30*time.Second) // 30s in the future

	expired := table.Cleanup(10 * time.Second)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired (deadline in future), got %d", len(expired))
	}
	ReleaseExpired(expired)
}

// TestSweepRetransmit verifies that SweepRetransmit correctly identifies
// UDP-range SynSent entries with retries remaining, calls the callback,
// and increments NegRound.
func TestSweepRetransmit(t *testing.T) {
	table := NewConnectionTable()

	// Add entries in the UDP source port range (50000-60999)
	table.AddSynSent(1, 10, 50000, 53, 100)   // UDP range
	table.AddSynSent(1, 11, 50001, 161, 200)   // UDP range
	table.AddSynSent(1, 12, 40000, 80, 300)    // TCP range — should be skipped
	table.AddSynSent(1, 13, 50002, 443, 400)   // UDP range

	// Mark one as Established — should be skipped (not SynSent)
	st, _ := table.Get(1, 13, 50002, 443)
	st.Status = StatusEstablished

	var swept []uint16
	table.SweepRetransmit(50000, 60999, 3, func(st *State) {
		swept = append(swept, st.DstPort)
	})

	// Should have swept exactly the 2 SynSent entries in UDP range
	if len(swept) != 2 {
		t.Fatalf("expected 2 swept, got %d: %v", len(swept), swept)
	}

	// Verify NegRound was incremented
	st1, _ := table.Get(1, 10, 50000, 53)
	if st1.NegRound != 1 {
		t.Errorf("NegRound should be 1 after first sweep, got %d", st1.NegRound)
	}

	// Sweep again — should still work (NegRound=1 < maxRetries=3)
	swept = nil
	table.SweepRetransmit(50000, 60999, 3, func(st *State) {
		swept = append(swept, st.DstPort)
	})
	if len(swept) != 2 {
		t.Fatalf("second sweep: expected 2, got %d", len(swept))
	}
	if st1.NegRound != 2 {
		t.Errorf("NegRound should be 2 after second sweep, got %d", st1.NegRound)
	}
}

// TestSweepRetransmitMaxRetries verifies that entries stop being swept
// once they reach maxRetries.
func TestSweepRetransmitMaxRetries(t *testing.T) {
	table := NewConnectionTable()
	table.AddSynSent(1, 10, 50000, 53, 100)

	// Sweep 3 times with maxRetries=2
	for i := 0; i < 3; i++ {
		table.SweepRetransmit(50000, 60999, 2, func(st *State) {})
	}

	st, _ := table.Get(1, 10, 50000, 53)
	if st.NegRound != 2 {
		t.Errorf("NegRound should cap at maxRetries=2, got %d", st.NegRound)
	}

	// One more sweep — should NOT fire callback
	var count int
	table.SweepRetransmit(50000, 60999, 2, func(st *State) { count++ })
	if count != 0 {
		t.Errorf("should not sweep after maxRetries reached, got %d callbacks", count)
	}
}
