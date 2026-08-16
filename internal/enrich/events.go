package enrich

import (
	"net/netip"
	"time"
)

type Stage string

const (
	StageReverseDNS Stage = "rdns"
	StageGeoASN     Stage = "geo/asn"
)

type EventKind uint8

const (
	EventStageStarted EventKind = iota + 1
	EventLookupCompleted
	EventStageProgress
	EventStageCompleted
)

type LookupOutcome uint8

const (
	LookupResolved LookupOutcome = iota + 1
	LookupNoData
	LookupFailed
)

type Event struct {
	Kind     EventKind
	Stage    Stage
	IP       netip.Addr
	Hostname string
	Metadata Metadata
	Outcome  LookupOutcome
	Err      error
	Current  int
	Total    int
	Duration time.Duration
}

type Observer func(Event)
