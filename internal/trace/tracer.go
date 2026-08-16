package trace

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/icmp"
)

type Tracer struct {
	Config  Config
	Observe Observer
}

func ResolveTarget(ctx context.Context, destination string) (netip.Addr, error) {
	if destination == "" {
		return netip.Addr{}, errors.New("destination is required")
	}
	if addr, err := netip.ParseAddr(destination); err == nil {
		addr = addr.Unmap()
		if !addr.Is4() {
			return netip.Addr{}, fmt.Errorf("IPv6 destination %q is not supported in v0.1", destination)
		}
		return addr, nil
	}

	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", destination)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %q: %w", destination, err)
	}
	if len(addresses) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %q: no IPv4 address found", destination)
	}
	return addresses[0].Unmap(), nil
}

func (t Tracer) Trace(ctx context.Context, destination string, target netip.Addr) (Result, error) {
	if err := t.Config.Validate(); err != nil {
		return Result{}, err
	}
	if !target.Is4() {
		return Result{}, errors.New("trace target must be a valid IPv4 address")
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return Result{}, privilegeError(err)
	}
	defer conn.Close()
	stopCancellationWatch := make(chan struct{})
	defer close(stopCancellationWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopCancellationWatch:
		}
	}()

	packetConn := conn.IPv4PacketConn()
	result := Result{
		Destination: destination,
		Target:      target,
		Probe:       "ICMP Echo",
		PacketSize:  t.Config.PacketSize,
		StartedAt:   time.Now(),
		Hops:        make([]Hop, 0, t.Config.MaxHops),
	}

	id := echoID()
	for ttl := 1; ttl <= t.Config.MaxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := packetConn.SetTTL(ttl); err != nil {
			return result, fmt.Errorf("set probe TTL to %d: %w", ttl, err)
		}
		t.emit(Event{Kind: EventProbeStarted, Hop: Hop{Number: ttl}})

		hop, err := probe(ctx, conn, target, id, ttl, t.Config)
		if err != nil {
			return result, err
		}
		result.Hops = append(result.Hops, hop)
		t.emit(Event{Kind: EventHopCompleted, Hop: hop})
		if hop.Reached {
			result.Reached = true
			break
		}
		if hop.Unreachable {
			break
		}
	}
	return result, nil
}

func (t Tracer) emit(event Event) {
	if t.Observe != nil {
		t.Observe(event)
	}
}

func echoID() int {
	var random [2]byte
	if _, err := cryptorand.Read(random[:]); err == nil {
		return int(binary.BigEndian.Uint16(random[:]))
	}
	return os.Getpid() & 0xffff
}

func privilegeError(err error) error {
	message := strings.ToLower(err.Error())
	if runtime.GOOS == "linux" && (errors.Is(err, os.ErrPermission) || strings.Contains(message, "operation not permitted") || strings.Contains(message, "permission denied")) {
		return fmt.Errorf("open raw ICMP socket: permission denied; run as root or grant CAP_NET_RAW to the pktpath binary: %w", err)
	}
	return fmt.Errorf("open raw ICMP socket: %w", err)
}
