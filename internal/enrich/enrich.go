package enrich

import (
	"context"
	"errors"
	"net/netip"
	"time"

	networkscope "github.com/ppp16bit/pktpath/internal/network"
	"github.com/ppp16bit/pktpath/internal/trace"
)

type GeoProvider interface {
	Lookup(context.Context, netip.Addr) (Metadata, error)
}

type Metadata struct {
	Hostname   string `json:"hostname,omitempty"`
	ASN        uint32 `json:"asn,omitempty"`
	Network    string `json:"network,omitempty"`
	City       string `json:"city,omitempty"`
	Region     string `json:"region,omitempty"`
	RegionCode string `json:"region_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

type HopInfo struct {
	Hop      trace.Hop
	Class    networkscope.Class
	Metadata Metadata
}

type Enricher struct {
	ReverseDNS bool
	Geo        GeoProvider
	RDNS       ReverseResolver
	Observe    Observer
}

func (e Enricher) Enrich(ctx context.Context, hops []trace.Hop) []HopInfo {
	result := make([]HopInfo, len(hops))
	resolver := e.RDNS
	if resolver == nil {
		resolver = SystemReverseResolver{}
	}
	for index, hop := range hops {
		result[index] = HopInfo{Hop: hop}
		if !hop.Timeout {
			result[index].Class = networkscope.Classify(hop.IP)
		}
	}
	if e.ReverseDNS {
		e.enrichReverseDNS(ctx, result, resolver)
	}
	if e.Geo != nil {
		e.enrichGeoASN(ctx, result)
	}
	return result
}

type geoResult struct {
	metadata Metadata
	err      error
}

func (e Enricher) enrichReverseDNS(ctx context.Context, result []HopInfo, resolver ReverseResolver) {
	started := time.Now()
	e.emit(Event{Kind: EventStageStarted, Stage: StageReverseDNS, Total: len(result)})
	for index := range result {
		info := &result[index]
		if !info.Hop.Timeout {
			hostname, err := resolver.Lookup(ctx, info.Hop.IP)
			event := Event{Kind: EventLookupCompleted, Stage: StageReverseDNS, IP: info.Hop.IP, Hostname: hostname, Err: err}
			switch {
			case err == nil && hostname != "":
				info.Metadata.Hostname = hostname
				event.Outcome = LookupResolved
			case err == nil || errors.Is(err, ErrNoPTR):
				event.Outcome = LookupNoData
			case err != nil:
				event.Outcome = LookupFailed
			}
			e.emit(event)
		}
		e.emit(Event{Kind: EventStageProgress, Stage: StageReverseDNS, Current: index + 1, Total: len(result)})
	}
	e.emit(Event{Kind: EventStageCompleted, Stage: StageReverseDNS, Current: len(result), Total: len(result), Duration: time.Since(started)})
}

func (e Enricher) enrichGeoASN(ctx context.Context, result []HopInfo) {
	started := time.Now()
	e.emit(Event{Kind: EventStageStarted, Stage: StageGeoASN, Total: len(result)})
	cache := make(map[netip.Addr]geoResult)
	for index := range result {
		info := &result[index]
		if !info.Hop.Timeout && networkscope.CanGeolocate(info.Hop.IP) {
			lookup, found := cache[info.Hop.IP]
			if !found {
				lookup.metadata, lookup.err = e.Geo.Lookup(ctx, info.Hop.IP)
				cache[info.Hop.IP] = lookup
			}
			event := Event{Kind: EventLookupCompleted, Stage: StageGeoASN, IP: info.Hop.IP, Metadata: lookup.metadata, Err: lookup.err}
			switch {
			case lookup.err != nil:
				event.Outcome = LookupFailed
			case lookup.metadata == (Metadata{}):
				event.Outcome = LookupNoData
			default:
				event.Outcome = LookupResolved
				if lookup.metadata.Hostname == "" {
					lookup.metadata.Hostname = info.Metadata.Hostname
				}
				info.Metadata = lookup.metadata
			}
			e.emit(event)
		}
		e.emit(Event{Kind: EventStageProgress, Stage: StageGeoASN, Current: index + 1, Total: len(result)})
	}
	e.emit(Event{Kind: EventStageCompleted, Stage: StageGeoASN, Current: len(result), Total: len(result), Duration: time.Since(started)})
}

func (e Enricher) emit(event Event) {
	if e.Observe != nil {
		e.Observe(event)
	}
}
