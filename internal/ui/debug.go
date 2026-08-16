package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/ppp16bit/pktpath/internal/enrich"
	"github.com/ppp16bit/pktpath/internal/trace"
)

type DebugRenderer struct {
	writer io.Writer
}

func NewDebugRenderer(writer io.Writer) *DebugRenderer {
	return &DebugRenderer{writer: writer}
}

func (renderer *DebugRenderer) Resolve(destination string, target netip.Addr, duration time.Duration) {
	_, _ = fmt.Fprintf(renderer.writer, "[resolve] %s → %s (%s)\n\n", destination, target, formatElapsed(duration))
}

func (renderer *DebugRenderer) ResolveFailed(destination string, err error, duration time.Duration) {
	_, _ = fmt.Fprintf(renderer.writer, "[resolve] %s → error: %v (%s)\n", destination, err, formatElapsed(duration))
}

func (renderer *DebugRenderer) Trace(event trace.Event) {
	if event.Kind != trace.EventHopCompleted {
		return
	}
	if event.Hop.Timeout {
		_, _ = fmt.Fprintf(renderer.writer, "[trace] hop=%-3d timeout\n", event.Hop.Number)
		return
	}
	_, _ = fmt.Fprintf(renderer.writer, "[trace] hop=%-3d addr=%-15s rtt=%s\n", event.Hop.Number, event.Hop.IP, formatRTT(event.Hop.RTT))
}

func (renderer *DebugRenderer) TraceCompleted(result trace.Result, duration time.Duration) {
	switch {
	case result.Reached:
		_, _ = fmt.Fprintln(renderer.writer, "[trace] destination reached")
	case len(result.Hops) > 0 && result.Hops[len(result.Hops)-1].Unreachable:
		_, _ = fmt.Fprintln(renderer.writer, "[trace] destination unreachable")
	default:
		_, _ = fmt.Fprintln(renderer.writer, "[trace] maximum hops reached without destination response")
	}
	_, _ = fmt.Fprintf(renderer.writer, "[trace] completed in %s\n\n", formatElapsed(duration))
}

func (renderer *DebugRenderer) TraceFailed(err error, duration time.Duration) {
	_, _ = fmt.Fprintf(renderer.writer, "[trace] error: %v\n", err)
	_, _ = fmt.Fprintf(renderer.writer, "[trace] stopped after %s\n", formatElapsed(duration))
}

func (renderer *DebugRenderer) Enrich(event enrich.Event) {
	switch event.Kind {
	case enrich.EventLookupCompleted:
		renderer.lookup(event)
	case enrich.EventStageCompleted:
		tag := "[" + string(event.Stage) + "]"
		_, _ = fmt.Fprintf(renderer.writer, "%-9s completed in %s\n\n", tag, formatElapsed(event.Duration))
	}
}

func (renderer *DebugRenderer) lookup(event enrich.Event) {
	var result string
	switch event.Outcome {
	case enrich.LookupResolved:
		if event.Stage == enrich.StageReverseDNS {
			result = event.Hostname
		} else {
			result = debugMetadata(event.Metadata)
		}
	case enrich.LookupNoData:
		if event.Stage == enrich.StageReverseDNS {
			result = "no PTR"
		} else {
			result = "no data"
		}
	case enrich.LookupFailed:
		result = lookupFailure(event.Stage, event.Err)
	default:
		return
	}
	tag := "[" + string(event.Stage) + "]"
	_, _ = fmt.Fprintf(renderer.writer, "%-9s %-15s → %s\n", tag, event.IP, result)
}

func (renderer *DebugRenderer) RenderingCompleted(duration time.Duration) {
	_, _ = fmt.Fprintf(renderer.writer, "[render] completed in %s\n", formatElapsed(duration))
}

func (renderer *DebugRenderer) TotalCompleted(duration time.Duration) {
	_, _ = fmt.Fprintf(renderer.writer, "[total] completed in %s\n", formatElapsed(duration))
}

func debugMetadata(metadata enrich.Metadata) string {
	sections := make([]string, 0, 2)
	network := make([]string, 0, 2)
	if metadata.ASN != 0 {
		network = append(network, fmt.Sprintf("AS%d", metadata.ASN))
	}
	if metadata.Network != "" {
		network = append(network, metadata.Network)
	}
	if len(network) > 0 {
		sections = append(sections, strings.Join(network, " "))
	}
	location := formatEstimatedLocation(metadata)
	if location != "" {
		sections = append(sections, location)
	}
	if len(sections) == 0 {
		return "no data"
	}
	return strings.Join(sections, " | ")
}

func lookupFailure(stage enrich.Stage, err error) string {
	if err == nil {
		return "lookup failed"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if stage == enrich.StageReverseDNS {
			return "DNS timeout"
		}
		return "request timeout"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		if stage == enrich.StageReverseDNS {
			return "DNS timeout"
		}
		return "request timeout"
	}
	return "error: " + err.Error()
}

func formatElapsed(duration time.Duration) string {
	switch {
	case duration < time.Millisecond:
		return duration.Round(time.Microsecond).String()
	case duration < time.Second:
		return duration.Round(time.Millisecond).String()
	default:
		return duration.Round(10 * time.Millisecond).String()
	}
}
