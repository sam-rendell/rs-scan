package banner

import (
	"rs_scan/internal/stack"
	"testing"
)

func BenchmarkArenaAlloc(b *testing.B) {
	a := NewArena(uint32(b.N+1), 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Alloc()
	}
}

func BenchmarkArenaAllocFree(b *testing.B) {
	a := NewArena(1024, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx, _, ok := a.Alloc()
		if !ok {
			b.Fatal("arena full")
		}
		a.Free(idx)
	}
}

func BenchmarkArenaGet(b *testing.B) {
	a := NewArena(1024, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Get(uint32(i) % 1024)
	}
}

func BenchmarkTXRingEnqueue(b *testing.B) {
	ring := NewTXRing(65536)
	req := TXRequest{DstIP: 0x0A000001, SrcPort: 40000, DstPort: 80, Seq: 1, Ack: 1, Flags: FlagACK}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ring.Enqueue(req) {
			// Drain to avoid full
			ring.DrainBatch(make([]TXRequest, 65536), 65536)
		}
	}
}

func BenchmarkTXRingEnqueueDrain(b *testing.B) {
	ring := NewTXRing(1024)
	req := TXRequest{DstIP: 0x0A000001, SrcPort: 40000, DstPort: 80, Seq: 1, Ack: 1, Flags: FlagACK}
	batch := make([]TXRequest, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ring.Enqueue(req)
		if ring.Len() >= 256 {
			ring.DrainBatch(batch, 256)
		}
	}
}

func BenchmarkProbeTableLookup(b *testing.B) {
	pt := NewProbeTable()
	// Add a few probes manually
	probe := &CompiledProbe{Name: "http", Hello: []byte("GET / HTTP/1.0\r\n\r\n"), RecvMax: 4096}
	pt.Probes = append(pt.Probes, probe)
	pt.ByPort[80] = probe
	pt.ByPort[8080] = probe
	pt.ByPort[443] = probe
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pt.LookupPort(uint16(i % 65536))
	}
}

func BenchmarkEngineHandleSynAck(b *testing.B) {
	arena := NewArena(uint32(b.N+1), 512)
	txRing := NewTXRing(65536)
	pt := NewProbeTable()
	probe := &CompiledProbe{Name: "http", Hello: []byte("GET / HTTP/1.0\r\n\r\n"), RecvMax: 4096, Phase1MS: 500}
	pt.Probes = append(pt.Probes, probe)
	pt.ByPort[80] = probe
	connTable := stack.NewConnectionTable()
	output := make(chan GrabResult, 100000)

	running := int32(1)
	engine := NewEngine(EngineConfig{
		Arena: arena, TXRing: txRing, Probes: pt, ConnTable: connTable,
		SrcIP: 0xC0A80001, Output: output, Phase1MS: 500, Running: &running,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := &stack.State{
			SrcIP: 0xC0A80001, DstIP: uint32(0x0A000000 + i),
			SrcPort: uint16(40000 + i%20000), DstPort: 80,
			Status: stack.StatusSynSent, Seq: uint32(i), Ack: uint32(i + 1),
		}
		engine.HandleSynAck(state, 64)
		// Drain TX ring periodically to prevent full
		if txRing.Len() > 60000 {
			txRing.DrainBatch(make([]TXRequest, 65536), 65536)
		}
	}
}

func BenchmarkEngineHandleData(b *testing.B) {
	arena := NewArena(10000, 512)
	txRing := NewTXRing(65536)
	pt := NewProbeTable()
	connTable := stack.NewConnectionTable()
	output := make(chan GrabResult, 100000)

	running := int32(1)
	engine := NewEngine(EngineConfig{
		Arena: arena, TXRing: txRing, Probes: pt, ConnTable: connTable,
		SrcIP: 0xC0A80001, Output: output, Phase1MS: 500, Running: &running,
	})

	// Pre-allocate states with arena slots
	states := make([]*stack.State, 10000)
	for i := 0; i < 10000; i++ {
		idx, _, _ := arena.Alloc()
		states[i] = &stack.State{
			SrcIP: 0xC0A80001, DstIP: uint32(0x0A000000 + i),
			SrcPort: uint16(40000 + i%20000), DstPort: 80,
			Status: stack.StatusEstablished,
			Seq: uint32(i), Ack: uint32(i + 1),
			ArenaSlot: idx, RecvMax: 512, RecvLen: 0,
			Step: stack.StepReceiving,
		}
	}

	payload := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := states[i%10000]
		// Reset for re-use
		st.RecvLen = 0
		st.Ack = uint32(i)
		engine.HandleData(st, payload, uint32(i), uint32(i+1), 64)
		// Drain output/ring periodically
		if txRing.Len() > 60000 {
			txRing.DrainBatch(make([]TXRequest, 65536), 65536)
		}
		for len(output) > 90000 {
			<-output
		}
	}
}
