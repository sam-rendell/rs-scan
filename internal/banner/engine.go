package banner

import (
	"rs_scan/internal/stack"
	"sync/atomic"
	"time"
)

// time import retained for EngineConfig.ConnTimeout and NewEngine duration conversion.

// GrabResult is sent to the output channel when a banner grab completes.
type GrabResult struct {
	IP     uint32
	Port   uint16
	TTL    uint8
	Probe  string
	Banner []byte
}

// Engine is the banner grab TCP state machine.
// It processes incoming packets, drives probe steps, and enqueues TX responses.
type Engine struct {
	arena      *Arena
	txRing     *TXRing
	probes     *ProbeTable
	connTable  *stack.ConnectionTable
	srcIP      uint32
	output     chan<- GrabResult
	phase1MS   int64 // default phase1 timeout in nanoseconds
	connTimeNS int64 // default connection timeout in nanoseconds
	running    *int32
}

// EngineConfig holds initialization parameters for the banner engine.
type EngineConfig struct {
	Arena        *Arena
	TXRing       *TXRing
	Probes       *ProbeTable
	ConnTable    *stack.ConnectionTable
	SrcIP        uint32
	Output       chan<- GrabResult
	Phase1MS     int // milliseconds to wait before sending hello
	ConnTimeout  time.Duration
	Running      *int32
}

// NewEngine creates a banner engine.
func NewEngine(cfg EngineConfig) *Engine {
	phase1 := int64(cfg.Phase1MS) * int64(time.Millisecond)
	if phase1 == 0 {
		phase1 = 500 * int64(time.Millisecond)
	}
	connT := cfg.ConnTimeout.Nanoseconds()
	if connT == 0 {
		connT = 5 * int64(time.Second)
	}
	return &Engine{
		arena:      cfg.Arena,
		txRing:     cfg.TXRing,
		probes:     cfg.Probes,
		connTable:  cfg.ConnTable,
		srcIP:      cfg.SrcIP,
		output:     cfg.Output,
		phase1MS:   phase1,
		connTimeNS: connT,
		running:    cfg.Running,
	}
}

// HandleSynAck is called when a SYN-ACK is received for a connection in StatusSynSent.
// It completes the handshake (sends ACK), allocates an arena slot, and sets up the grab state.
// Returns true if banner grab was initiated, false if arena is full (log as OPEN only).
func (e *Engine) HandleSynAck(state *stack.State, remoteTTL uint8) bool {
	probe := e.probes.LookupPort(state.DstPort)

	// Allocate arena slot
	slotID, _, ok := e.arena.Alloc()
	if !ok {
		return false // arena full — back-pressure
	}

	now := stack.NowNano()

	// Update connection state for banner grab
	state.Status = stack.StatusEstablished
	state.Updated = now // refresh so Cleanup doesn't expire based on SynSent time
	state.ArenaSlot = slotID
	state.RecvMax = probe.RecvMax
	state.ProbeID = e.probes.ProbeID(probe)
	state.Step = stack.StepWaitForData
	state.ConnDeadline = now + e.connTimeNS

	if probe.Hello != nil {
		// Active probe: set phase1 timer
		phase1 := int64(probe.Phase1MS) * int64(time.Millisecond)
		if phase1 == 0 {
			phase1 = e.phase1MS
		}
		state.Phase1Deadline = now + phase1
	}
	// Passive probes: Phase1Deadline stays 0 (never fire hello)

	// Send ACK to complete the handshake
	e.txRing.Enqueue(TXRequest{
		DstIP:   state.DstIP,
		SrcPort: state.SrcPort,
		DstPort: state.DstPort,
		Seq:     state.Seq,
		Ack:     state.Ack,
		Flags:   FlagACK,
	})

	return true
}

// HandleData is called when a DATA packet arrives for an established/banner-grab connection.
// It appends the payload to the arena slot, sends an ACK, and checks completion.
func (e *Engine) HandleData(state *stack.State, payload []byte, seq, ack uint32, remoteTTL uint8) {
	if state.ArenaSlot == stack.NoArenaSlot {
		return
	}

	// Update TCP state
	state.Ack = seq + uint32(len(payload))
	state.Updated = stack.NowNano()

	// Append to arena
	slot := e.arena.Get(state.ArenaSlot)
	if slot == nil {
		return
	}

	n := copy(slot[state.RecvLen:], payload)
	state.RecvLen += uint16(n)

	// Send ACK for received data
	e.txRing.Enqueue(TXRequest{
		DstIP:   state.DstIP,
		SrcPort: state.SrcPort,
		DstPort: state.DstPort,
		Seq:     state.Seq,
		Ack:     state.Ack,
		Flags:   FlagACK,
	})

	// Check if we've negotiated (telnet IAC handling)
	if state.Step == stack.StepWaitForData || state.Step == stack.StepReceiving {
		probe := e.probeForState(state)
		if probe != nil && probe.HasNegotiate {
			e.runNegotiate(state, probe)
		}
	}

	// Move to receiving state if still waiting
	if state.Step == stack.StepWaitForData || state.Step == stack.StepHelloSent {
		state.Step = stack.StepReceiving
	}

	// Check recv limit
	if state.RecvLen >= state.RecvMax {
		e.finalize(state, remoteTTL)
	}
}

// HandleFin is called when a FIN is received. Finalize the grab.
func (e *Engine) HandleFin(state *stack.State, seq, ack uint32, remoteTTL uint8) {
	// ACK the FIN
	state.Ack = seq + 1
	e.txRing.Enqueue(TXRequest{
		DstIP:   state.DstIP,
		SrcPort: state.SrcPort,
		DstPort: state.DstPort,
		Seq:     state.Seq,
		Ack:     state.Ack,
		Flags:   FlagACK,
	})

	e.finalize(state, remoteTTL)
}

// HandleRst is called when a RST is received. Clean up without sending anything.
// Per RFC 793: RST segments must not generate RSTs.
func (e *Engine) HandleRst(state *stack.State, remoteTTL uint8) {
	if state.ArenaSlot == stack.NoArenaSlot {
		return
	}

	if state.RecvLen > 0 {
		e.emitResult(state, remoteTTL)
	}

	e.arena.Free(state.ArenaSlot)
	state.ArenaSlot = stack.NoArenaSlot
	state.Status = stack.StatusClosed
}

// CheckTimers scans for phase1 deadlines and connection deadlines.
// Called periodically from the manager ticker.
// Returns the number of expired connections cleaned up.
func (e *Engine) CheckTimers(expired []*stack.State) int {
	cleaned := 0

	for _, st := range expired {
		if st.ArenaSlot != stack.NoArenaSlot {
			// This was a banner grab connection — emit result if we have data
			if st.RecvLen > 0 {
				e.emitResult(st, 0)
			}

			// Send RST so the remote doesn't sit in ESTABLISHED until its own timeout
			e.txRing.Enqueue(TXRequest{
				DstIP:   st.DstIP,
				SrcPort: st.SrcPort,
				DstPort: st.DstPort,
				Seq:     st.Seq,
				Ack:     st.Ack,
				Flags:   FlagRST,
			})

			e.arena.Free(st.ArenaSlot)
			st.ArenaSlot = stack.NoArenaSlot
			cleaned++
		}
	}

	return cleaned
}

// CheckPhase1 checks if any established connections have hit their phase1 deadline.
// Should be called periodically (e.g. every 100ms from the manager).
func (e *Engine) CheckPhase1() {
	if atomic.LoadInt32(e.running) != 1 {
		return
	}

	e.connTable.SweepPhase1(stack.NowNano(), func(st *stack.State) {
		probe := e.probeForState(st)
		if probe == nil || probe.Hello == nil {
			return
		}
		// Send hello payload
		e.txRing.Enqueue(TXRequest{
			DstIP:   st.DstIP,
			SrcPort: st.SrcPort,
			DstPort: st.DstPort,
			Seq:     st.Seq,
			Ack:     st.Ack,
			Flags:   FlagPSHACK,
			Payload: probe.Hello,
		})
		st.Step = stack.StepHelloSent
		st.Seq += uint32(len(probe.Hello))
		st.Phase1Deadline = 0 // disarm
	})
}

// runNegotiate applies negotiate rules to data in the arena slot.
func (e *Engine) runNegotiate(state *stack.State, probe *CompiledProbe) {
	if state.NegRound >= probe.NegMaxRounds {
		return
	}

	slot := e.arena.Get(state.ArenaSlot)
	if slot == nil {
		return
	}
	data := slot[:state.RecvLen]

	// Check escape bytes
	for _, esc := range probe.EscapeOn {
		for _, b := range data {
			if b == esc {
				state.Step = stack.StepReceiving // abort negotiate, just receive
				return
			}
		}
	}

	// Scan for matching negotiate rules
	var totalSent uint16
	for i := 0; i+2 < len(data); i++ {
		for _, rule := range probe.NegRules {
			if matchNegRule(data[i:], rule) {
				reply := buildNegReply(rule, data[i:])
				e.txRing.Enqueue(TXRequest{
					DstIP:   state.DstIP,
					SrcPort: state.SrcPort,
					DstPort: state.DstPort,
					Seq:     state.Seq,
					Ack:     state.Ack,
					Flags:   FlagPSHACK,
					Payload: reply,
				})
				state.Seq += uint32(len(reply))
				totalSent += uint16(len(reply))
				state.NegRound++

				if state.NegRound >= probe.NegMaxRounds || totalSent >= probe.NegMaxBytes {
					state.Step = stack.StepReceiving
					return
				}
				break // move to next byte position
			}
		}
	}

	state.Step = stack.StepNegotiating
}

// matchNegRule checks if data starting at pos matches a negotiate rule.
func matchNegRule(data []byte, rule NegRule) bool {
	if len(data) < len(rule.When) {
		return false
	}
	for i, b := range rule.When {
		if b == WildcardByte {
			continue // wildcard matches anything
		}
		if data[i] != b {
			return false
		}
	}
	return true
}

// buildNegReply builds the reply bytes, substituting wildcard captures.
func buildNegReply(rule NegRule, data []byte) []byte {
	reply := make([]byte, len(rule.Reply))
	copy(reply, rule.Reply)
	// Replace wildcard backrefs with captured byte
	if rule.WildcardAt >= 0 && rule.WildcardAt < len(data) {
		captured := data[rule.WildcardAt]
		for i, b := range reply {
			if b == WildcardByte {
				reply[i] = captured
			}
		}
	}
	return reply
}

// finalize completes a banner grab: emits result, sends RST, frees arena slot.
func (e *Engine) finalize(state *stack.State, ttl uint8) {
	if state.ArenaSlot == stack.NoArenaSlot {
		return
	}

	if state.RecvLen > 0 {
		e.emitResult(state, ttl)
	}

	// Send RST to tear down the connection
	e.txRing.Enqueue(TXRequest{
		DstIP:   state.DstIP,
		SrcPort: state.SrcPort,
		DstPort: state.DstPort,
		Seq:     state.Seq,
		Ack:     state.Ack,
		Flags:   FlagRST,
	})

	e.arena.Free(state.ArenaSlot)
	state.ArenaSlot = stack.NoArenaSlot
	state.Status = stack.StatusClosed
}

// emitResult sends a GrabResult to the output channel.
func (e *Engine) emitResult(state *stack.State, ttl uint8) {
	slot := e.arena.Get(state.ArenaSlot)
	if slot == nil {
		return
	}

	// Copy banner data out of arena (arena slot will be freed after this)
	banner := make([]byte, state.RecvLen)
	copy(banner, slot[:state.RecvLen])

	probe := e.probeForState(state)
	name := "generic"
	if probe != nil {
		name = probe.Name
	}

	select {
	case e.output <- GrabResult{
		IP:     state.DstIP,
		Port:   state.DstPort,
		TTL:    ttl,
		Probe:  name,
		Banner: banner,
	}:
	default:
		// Output channel full — drop (shouldn't happen with buffered channel)
	}
}

func (e *Engine) probeForState(state *stack.State) *CompiledProbe {
	if int(state.ProbeID) < len(e.probes.Probes) {
		return e.probes.Probes[state.ProbeID]
	}
	return e.probes.Default
}
