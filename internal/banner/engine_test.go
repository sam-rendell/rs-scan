package banner

import (
	"rs_scan/internal/stack"
	"testing"
	"time"
)

func newTestEngine(t *testing.T) (*Engine, *Arena, *TXRing, chan GrabResult) {
	t.Helper()
	arena := NewArena(1000, 512)
	txRing := NewTXRing(4096)
	pt := NewProbeTable()
	probe := &CompiledProbe{
		Name: "ssh", Hello: []byte("SSH-2.0-scanner\r\n"),
		RecvMax: 256, Phase1MS: 500,
	}
	pt.Probes = append(pt.Probes, probe)
	pt.ByPort[22] = probe
	connTable := stack.NewConnectionTable()
	output := make(chan GrabResult, 100)

	running := int32(1)
	engine := NewEngine(EngineConfig{
		Arena: arena, TXRing: txRing, Probes: pt, ConnTable: connTable,
		SrcIP: 0xC0A80001, Output: output, Phase1MS: 500,
		ConnTimeout: 5 * time.Second, Running: &running,
	})
	return engine, arena, txRing, output
}

// TestHandleSynAck_UpdatesTimestamp verifies that HandleSynAck refreshes
// state.Updated so that Cleanup doesn't expire the connection based on
// the original SynSent timestamp. Without this fix, banner grab connections
// were being prematurely cleaned up.
func TestHandleSynAck_UpdatesTimestamp(t *testing.T) {
	engine, _, _, _ := newTestEngine(t)

	// Simulate a state created 4 seconds ago (near timeout)
	oldTime := stack.NowNano() - 4*int64(time.Second)
	state := &stack.State{
		SrcIP: 0xC0A80001, DstIP: 0x0A000001,
		SrcPort: 40000, DstPort: 22,
		Status:  stack.StatusSynSent,
		Seq:     1000, Ack: 2001,
		Updated: oldTime,
	}

	beforeCall := stack.NowNano()
	ok := engine.HandleSynAck(state, 64)
	if !ok {
		t.Fatal("HandleSynAck returned false (arena should not be full)")
	}

	// state.Updated must have been refreshed to ~now
	if state.Updated < beforeCall {
		t.Fatalf("HandleSynAck did not update state.Updated: got %d, want >= %d\n"+
			"This causes premature Cleanup expiry of banner grab connections.",
			state.Updated, beforeCall)
	}
	if state.Status != stack.StatusEstablished {
		t.Fatalf("expected StatusEstablished, got %d", state.Status)
	}
}

// TestHandleSynAck_EnqueuesACK verifies that a handshake ACK is enqueued.
func TestHandleSynAck_EnqueuesACK(t *testing.T) {
	engine, _, txRing, _ := newTestEngine(t)

	state := &stack.State{
		SrcIP: 0xC0A80001, DstIP: 0x0A000001,
		SrcPort: 40000, DstPort: 22,
		Status: stack.StatusSynSent, Seq: 100, Ack: 200,
		Updated: stack.NowNano(),
	}

	engine.HandleSynAck(state, 64)

	req, ok := txRing.Dequeue()
	if !ok {
		t.Fatal("HandleSynAck did not enqueue ACK")
	}
	if req.Flags != FlagACK {
		t.Fatalf("expected ACK flag (0x%02x), got 0x%02x", FlagACK, req.Flags)
	}
	if req.DstIP != 0x0A000001 {
		t.Fatalf("wrong DstIP in ACK: %08x", req.DstIP)
	}
}

// TestHandleSynAck_AllocatesArena verifies arena slot assignment.
func TestHandleSynAck_AllocatesArena(t *testing.T) {
	engine, _, _, _ := newTestEngine(t)

	state := &stack.State{
		SrcIP: 0xC0A80001, DstIP: 0x0A000001,
		SrcPort: 40000, DstPort: 22,
		Status: stack.StatusSynSent, Seq: 100, Ack: 200,
		Updated: stack.NowNano(), ArenaSlot: stack.NoArenaSlot,
	}

	ok := engine.HandleSynAck(state, 64)
	if !ok {
		t.Fatal("HandleSynAck returned false")
	}
	if state.ArenaSlot == stack.NoArenaSlot {
		t.Fatal("HandleSynAck did not assign arena slot")
	}
	if state.Step != stack.StepWaitForData {
		t.Fatalf("expected StepWaitForData, got %d", state.Step)
	}
}

// TestHandleData_AppendsAndACKs verifies data appending and ACK generation.
func TestHandleData_AppendsAndACKs(t *testing.T) {
	engine, arena, txRing, _ := newTestEngine(t)

	slotID, _, _ := arena.Alloc()
	state := &stack.State{
		SrcIP: 0xC0A80001, DstIP: 0x0A000001,
		SrcPort: 40000, DstPort: 22,
		Status: stack.StatusEstablished,
		Seq: 100, Ack: 200,
		ArenaSlot: slotID, RecvMax: 256, RecvLen: 0,
		Step: stack.StepWaitForData,
		Updated: stack.NowNano(),
	}

	payload := []byte("SSH-2.0-OpenSSH_8.9\r\n")
	engine.HandleData(state, payload, 200, 100, 64)

	// Check data was appended
	if state.RecvLen != uint16(len(payload)) {
		t.Fatalf("RecvLen = %d, want %d", state.RecvLen, len(payload))
	}

	// Check ACK was enqueued
	req, ok := txRing.Dequeue()
	if !ok {
		t.Fatal("HandleData did not enqueue ACK")
	}
	if req.Flags != FlagACK {
		t.Fatalf("expected ACK, got 0x%02x", req.Flags)
	}
	if req.Ack != 200+uint32(len(payload)) {
		t.Fatalf("ACK number wrong: %d, want %d", req.Ack, 200+uint32(len(payload)))
	}
}

// TestFullPipeline_SynAckToFinalize tests the complete banner grab lifecycle:
// SYN-ACK → ACK → Data → finalize → GrabResult emitted.
func TestFullPipeline_SynAckToFinalize(t *testing.T) {
	engine, _, txRing, output := newTestEngine(t)

	state := &stack.State{
		SrcIP: 0xC0A80001, DstIP: 0x0A000001,
		SrcPort: 40000, DstPort: 22,
		Status: stack.StatusSynSent,
		Seq: 100, Ack: 200,
		Updated: stack.NowNano(), ArenaSlot: stack.NoArenaSlot,
	}

	// Step 1: SYN-ACK
	ok := engine.HandleSynAck(state, 64)
	if !ok {
		t.Fatal("HandleSynAck failed")
	}
	// Drain the handshake ACK
	txRing.Dequeue()

	// Step 2: Data arrives
	banner := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
	engine.HandleData(state, banner, state.Ack, state.Seq, 64)
	txRing.Dequeue() // data ACK

	// Step 3: FIN arrives
	engine.HandleFin(state, state.Ack, state.Seq, 64)

	// Should have: FIN-ACK + RST in tx ring
	finAck, ok := txRing.Dequeue()
	if !ok {
		t.Fatal("expected FIN ACK in tx ring")
	}
	if finAck.Flags != FlagACK {
		t.Fatalf("expected ACK for FIN, got 0x%02x", finAck.Flags)
	}
	rst, ok := txRing.Dequeue()
	if !ok {
		t.Fatal("expected RST in tx ring")
	}
	if rst.Flags != FlagRST {
		t.Fatalf("expected RST, got 0x%02x", rst.Flags)
	}

	// GrabResult should be in output channel
	select {
	case result := <-output:
		if result.IP != 0x0A000001 {
			t.Fatalf("wrong IP: %08x", result.IP)
		}
		if result.Port != 22 {
			t.Fatalf("wrong port: %d", result.Port)
		}
		if string(result.Banner) != string(banner) {
			t.Fatalf("wrong banner: %q", result.Banner)
		}
		if result.Probe != "ssh" {
			t.Fatalf("wrong probe name: %s", result.Probe)
		}
	default:
		t.Fatal("no GrabResult emitted")
	}

	// Arena slot should be freed
	if state.ArenaSlot != stack.NoArenaSlot {
		t.Fatal("arena slot not freed after finalize")
	}
	if state.Status != stack.StatusClosed {
		t.Fatalf("expected StatusClosed, got %d", state.Status)
	}
}

// TestHandleRst_NoRSTBack verifies RFC 793 compliance: RST must not generate RST.
func TestHandleRst_NoRSTBack(t *testing.T) {
	engine, arena, txRing, output := newTestEngine(t)

	slotID, _, _ := arena.Alloc()
	state := &stack.State{
		SrcIP: 0xC0A80001, DstIP: 0x0A000001,
		SrcPort: 40000, DstPort: 22,
		Status: stack.StatusEstablished,
		ArenaSlot: slotID, RecvLen: 0,
		Updated: stack.NowNano(),
	}

	engine.HandleRst(state, 64)

	// No packets should be enqueued (RFC 793: RST must not generate RST)
	_, ok := txRing.Dequeue()
	if ok {
		t.Fatal("HandleRst enqueued a packet — RFC 793 violation")
	}

	// No result emitted (RecvLen=0)
	select {
	case <-output:
		t.Fatal("unexpected GrabResult for RST with no data")
	default:
	}

	if state.Status != stack.StatusClosed {
		t.Fatalf("expected StatusClosed, got %d", state.Status)
	}
}

// TestCheckTimers_SendsRST verifies that expired banner connections get RST.
func TestCheckTimers_SendsRST(t *testing.T) {
	engine, arena, txRing, _ := newTestEngine(t)

	slotID, _, _ := arena.Alloc()
	state := &stack.State{
		SrcIP: 0xC0A80001, DstIP: 0x0A000001,
		SrcPort: 40000, DstPort: 22,
		Status: stack.StatusEstablished,
		ArenaSlot: slotID, RecvLen: 0,
		Seq: 500, Ack: 600,
		Updated: stack.NowNano(),
	}

	expired := []*stack.State{state}
	cleaned := engine.CheckTimers(expired)
	if cleaned != 1 {
		t.Fatalf("expected 1 cleaned, got %d", cleaned)
	}

	req, ok := txRing.Dequeue()
	if !ok {
		t.Fatal("CheckTimers did not enqueue RST for expired connection")
	}
	if req.Flags != FlagRST {
		t.Fatalf("expected RST, got 0x%02x", req.Flags)
	}

	if state.ArenaSlot != stack.NoArenaSlot {
		t.Fatal("arena slot not freed")
	}
}
