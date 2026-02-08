package ui

import "time"

// EventType classifies scan events for the UI.
type EventType int

const (
	EvtOpen    EventType = iota
	EvtBanner
	EvtTimeout
	EvtClosed
	EvtStats
	EvtInfo
	EvtDone
)

// ScanEvent is a single event emitted by the scan engine to the UI.
type ScanEvent struct {
	Type         EventType
	IP           string
	Port         uint16
	Proto        string
	TTL          uint8
	Banner       string
	Probe        string
	Msg          string // for EvtInfo
	OSFamily     string // from classifier
	OSConfidence string // "high"/"medium"/"low"
}

// ScanStats contains periodic stats for the UI.
type ScanStats struct {
	Sent     uint64
	Recv     uint64
	Open     uint64
	Banners  uint64
	Drops    uint64
	Elapsed  time.Duration
	Progress float64 // 0.0 - 1.0
	Rate     float64
}

// Mode selects the UI output mode.
type Mode int

const (
	ModeTUI    Mode = iota // full bubbletea interactive
	ModeText               // simple \r status + \n results
	ModeSilent             // no terminal output
)
