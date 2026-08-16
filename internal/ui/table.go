package ui

import (
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/ppp16bit/pktpath/internal/enrich"
	networkscope "github.com/ppp16bit/pktpath/internal/network"
	"github.com/ppp16bit/pktpath/internal/trace"
)

type HumanOptions struct {
	Color       bool
	ShowPrivate bool
}

func WriteHuman(writer io.Writer, result trace.Result, hops []enrich.HopInfo, options HumanOptions) error {
	renderer := lipgloss.NewRenderer(writer)
	if !options.Color {
		renderer.SetColorProfile(termenv.Ascii)
	}
	title := renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	dim := renderer.NewStyle().Foreground(lipgloss.Color("245"))
	header := renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	good := renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	warn := renderer.NewStyle().Foreground(lipgloss.Color("214"))

	if _, err := fmt.Fprintf(writer, "\n  %s %s\n\n", title.Render("pktpath →"), result.Destination+" ("+result.Target.String()+")"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  Probe: %s\n  Size:  %d B total IPv4 packet\n\n", result.Probe, result.PacketSize); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  %s\n", header.Render(fmt.Sprintf("%-4s %-15s %-28s %-28s %-24s %9s", "HOP", "ADDRESS", "HOSTNAME", "ESTIMATED LOCATION", "NETWORK", "RTT"))); err != nil {
		return err
	}
	for _, info := range hops {
		address, hostname, location, network, rtt := displayFields(info, options.ShowPrivate)
		row := fmt.Sprintf("%-4d %-15s %-28s %-28s %-24s %9s", info.Hop.Number, truncate(address, 15), truncate(hostname, 28), truncate(location, 28), truncate(network, 24), rtt)
		if info.Hop.Timeout {
			row = warn.Render(row)
		}
		if _, err := fmt.Fprintf(writer, "  %s\n", row); err != nil {
			return err
		}
	}

	if result.Reached {
		_, err := fmt.Fprintf(writer, "\n  %s\n", good.Render(fmt.Sprintf("✓ reached %s in %d hops", result.Destination, len(result.Hops))))
		return err
	}
	if len(result.Hops) > 0 && result.Hops[len(result.Hops)-1].Unreachable {
		_, err := fmt.Fprintf(writer, "\n  %s\n", warn.Render(fmt.Sprintf("! destination reported unreachable after %d hops", len(result.Hops))))
		return err
	}
	_, err := fmt.Fprintf(writer, "\n  %s\n", dim.Render(fmt.Sprintf("destination not reached within %d hops", len(result.Hops))))
	return err
}

func displayFields(info enrich.HopInfo, showPrivate bool) (address, hostname, location, network, rtt string) {
	if info.Hop.Timeout {
		return "*", "—", "timeout", "—", "—"
	}
	address = info.Hop.IP.String()
	if !showPrivate {
		address = maskInternalAddress(info.Hop.IP, info.Class)
	}
	hostname = placeholder(info.Metadata.Hostname)
	location = locationFor(info)
	network = placeholder(info.Metadata.Network)
	if info.Metadata.ASN != 0 {
		if network == "—" {
			network = fmt.Sprintf("AS%d", info.Metadata.ASN)
		} else {
			network = fmt.Sprintf("AS%d %s", info.Metadata.ASN, network)
		}
	}
	rtt = formatRTT(info.Hop.RTT)
	return
}

func maskInternalAddress(address netip.Addr, class networkscope.Class) string {
	if !address.Is4() {
		return address.String()
	}
	bytes := address.As4()
	switch class {
	case networkscope.ClassPrivate:
		switch bytes[0] {
		case 10:
			return "10.x.x.x"
		case 172:
			return "172.x.x.x"
		case 192:
			return "192.168.x.x"
		}
	case networkscope.ClassShared:
		return "100.x.x.x"
	}
	return address.String()
}

func locationFor(info enrich.HopInfo) string {
	if location := formatEstimatedLocation(info.Metadata); location != "" {
		return location
	}
	switch info.Class {
	case networkscope.ClassPrivate:
		if info.Hop.Number == 1 {
			return "local"
		}
		return "private"
	case networkscope.ClassLoopback:
		return "local"
	case networkscope.ClassShared:
		return "shared / possible CGNAT"
	case networkscope.ClassLinkLocal:
		return "link-local"
	case networkscope.ClassMulticast:
		return "multicast"
	default:
		return "—"
	}
}

func formatRTT(duration time.Duration) string {
	if duration < time.Millisecond {
		return fmt.Sprintf("%.3fms", float64(duration)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.1fms", float64(duration)/float64(time.Millisecond))
}

func truncate(value string, width int) string {
	characters := []rune(value)
	if len(characters) <= width {
		return value
	}
	if width <= 1 {
		return string(characters[:width])
	}
	return string(characters[:width-1]) + "…"
}

func placeholder(value string) string {
	if value == "" {
		return "—"
	}
	return value
}
