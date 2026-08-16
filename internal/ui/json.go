package ui

import (
	"encoding/json"
	"io"
	"time"

	"github.com/ppp16bit/pktpath/internal/enrich"
	"github.com/ppp16bit/pktpath/internal/trace"
)

type jsonLocation struct {
	City       string `json:"city,omitempty"`
	Region     string `json:"region,omitempty"`
	RegionCode string `json:"region_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

type jsonHop struct {
	Number            int           `json:"number"`
	IP                string        `json:"ip,omitempty"`
	RTTMilliseconds   *float64      `json:"rtt_ms"`
	ReceivedAt        *time.Time    `json:"received_at"`
	Timeout           bool          `json:"timeout"`
	Reached           bool          `json:"reached"`
	Unreachable       bool          `json:"unreachable"`
	Classification    string        `json:"classification,omitempty"`
	Hostname          string        `json:"hostname,omitempty"`
	ASN               uint32        `json:"asn,omitempty"`
	Network           string        `json:"network,omitempty"`
	EstimatedLocation *jsonLocation `json:"estimated_location,omitempty"`
}

type jsonResult struct {
	Destination         string    `json:"destination"`
	Target              string    `json:"target"`
	Probe               string    `json:"probe"`
	PacketSizeBytes     int       `json:"packet_size_bytes"`
	PacketSizeSemantics string    `json:"packet_size_semantics"`
	StartedAt           time.Time `json:"started_at"`
	Reached             bool      `json:"reached"`
	Hops                []jsonHop `json:"hops"`
}

func WriteJSON(writer io.Writer, result trace.Result, hops []enrich.HopInfo) error {
	output := jsonResult{
		Destination:         result.Destination,
		Target:              result.Target.String(),
		Probe:               result.Probe,
		PacketSizeBytes:     result.PacketSize,
		PacketSizeSemantics: "intended total IPv4 packet size, including 20-byte IPv4 and 8-byte ICMP headers",
		StartedAt:           result.StartedAt,
		Reached:             result.Reached,
		Hops:                make([]jsonHop, 0, len(hops)),
	}
	for _, info := range hops {
		hop := jsonHop{
			Number:         info.Hop.Number,
			Timeout:        info.Hop.Timeout,
			Reached:        info.Hop.Reached,
			Unreachable:    info.Hop.Unreachable,
			Classification: string(info.Class),
			Hostname:       info.Metadata.Hostname,
			ASN:            info.Metadata.ASN,
			Network:        info.Metadata.Network,
		}
		if !info.Hop.Timeout {
			hop.IP = info.Hop.IP.String()
			milliseconds := float64(info.Hop.RTT) / float64(time.Millisecond)
			hop.RTTMilliseconds = &milliseconds
			receivedAt := info.Hop.ReceivedAt
			hop.ReceivedAt = &receivedAt
		}
		if info.Metadata.City != "" || info.Metadata.Region != "" || info.Metadata.RegionCode != "" || info.Metadata.Country != "" {
			hop.EstimatedLocation = &jsonLocation{
				City: info.Metadata.City, Region: info.Metadata.Region, RegionCode: info.Metadata.RegionCode, Country: info.Metadata.Country,
			}
		}
		output.Hops = append(output.Hops, hop)
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
