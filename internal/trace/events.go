package trace

type EventKind uint8

const (
	EventProbeStarted EventKind = iota + 1
	EventHopCompleted
)

type Event struct {
	Kind EventKind
	Hop  Hop
}

type Observer func(Event)
